import os, pathlib, logging, json, hashlib, time, stat


class Metasnap(object):
	__slots__ = (
		"_set_status_line",
		"_status_general",
		"_status_hash",
		"_snapshot_path",
		"_chunk_size",
		"_log",
	)

	EXTRACTORS_SUPPORTED_NOOP = {"none"}
	EXTRACTORS_SUPPORTED_STAT = {"st_mode", "st_size", "st_ctime", "st_ctime_ns", "st_mtime", "st_mtime_ns"}
	EXTRACTORS_SUPPORTED_HASH = set(hashlib.algorithms_guaranteed)
	EXTRACTORS_ALWAYS         = ("st_mode", "st_size")

	@classmethod
	def all_supported_extractors(cls):
		return (
			list(cls.EXTRACTORS_SUPPORTED_NOOP) +
			list(cls.EXTRACTORS_SUPPORTED_STAT) +
			list(cls.EXTRACTORS_SUPPORTED_HASH)
		)

	@classmethod
	def is_supported_extractor(cls, name):
		if name in cls.EXTRACTORS_SUPPORTED_NOOP:
			return True
		if name in cls.EXTRACTORS_SUPPORTED_STAT:
			return True
		if name in cls.EXTRACTORS_SUPPORTED_HASH:
			return True
		return False

	def __init__(self, snapshot_dir, *, status_line_setter=None, chunk_size=(512 * 2014)):
		self._log = logging.getLogger(__name__)
		self._set_status_line = status_line_setter
		if self._set_status_line is None:
			self._set_status_line = lambda i, s: None
		self._snapshot_path = self._ensure_snapshot_folder(pathlib.Path(snapshot_dir))
		self._chunk_size = chunk_size
		self._status_general = None
		self._status_hash = None

	async def update(self, path, *, filename_hash_algo="sha1", filename_list_hash_algo="sha1", meta_extractors):
		meta_extractors = set([*self.EXTRACTORS_ALWAYS, *(meta_extractors or [])])
		self._log.info("Updating %r of %r in %r snapshot", meta_extractors, os.fspath(path) , os.fspath(self._snapshot_path))

		path = pathlib.Path(path)
		files_input = self._traverse(path)

		self._log.info("Writing file list metadata.")
		await self.write_snapshot_meta(
			files_input,
			filename_hash_algo=filename_hash_algo,
			filename_list_hash_algo=filename_list_hash_algo
		)

		self._log.info("Hashing files.")

		num_files = len(files_input)
		num_files_processed = 0
		num_files_skipped = 0
		for fn in files_input:
			progress_status = "[{:7.2f}%] {:,} files processed, of which {:,} skipped.".format(
				(10000 * num_files_processed / num_files) / 100.0,
				num_files_processed,
				num_files_skipped,
			)
			self._set_status_general(progress_status)
			f_info_path = await self.get_file_info_path(filename=fn, filename_hash_algo=filename_hash_algo)
			if not os.path.exists(f_info_path):
				f_path = path / fn
				f_info = await self.file_info(f_path, meta_extractors=meta_extractors, return_error=True)
				if f_info.get("error", None):
					self._log.info("Failed to hash file %r - %s", os.fspath(f_path), f_info.get("error"))
				else:
					self.write_json_file(f_info_path, f_info)
			else:
				num_files_skipped += 1
			num_files_processed += 1
		self._set_status_general(None)
		self._log.info("%s files processed of which %s skipped.",
			"{:,}".format(num_files_processed),
			"{:,}".format(num_files_skipped),
		)

	async def check(self, path, *, meta_extractors):
		self._log.info("Checking %r of %r against %r", meta_extractors, os.fspath(path), os.fspath(self._snapshot_path))

		path = pathlib.Path(path)

		files_matching = {}
		files_changed = {}
		files_missing = []
		files_new = []

		files_input = set(self._traverse(path))
		files_snapshot, filename_hash_algo = await self.load_snapshot_meta()
		files_snapshot = set(files_snapshot)
		num_files = len(files_snapshot)
		num_files_processed = 0
		progress_report_fmt = "Processed {:,} files of which {:,} were matching, {:,} has changed, {:,} were missing, and {:,} are new."
		while files_snapshot:
			progress_status = ("[{:7.2f}%] " + progress_report_fmt).format(
				(10000 * num_files_processed / num_files) / 100.0,
				num_files_processed,
				len(files_matching),
				len(files_changed),
				len(files_missing),
				len(files_new),
			)
			self._set_status_general(progress_status)
			fn_snapshot = files_snapshot.pop()
			if fn_snapshot in files_input:
				files_input.remove(fn_snapshot)
				f_snapshot_info_path = await self.get_file_info_path(filename=fn_snapshot, filename_hash_algo=filename_hash_algo)
				if f_snapshot_info_path.exists():
					f_snapshot_info = self.read_json_file(f_snapshot_info_path)
				else:
					f_snapshot_info = {"error": "metadata not in snapshot"}

				f_info = await self.file_info(
					path / fn_snapshot,
					meta_extractors=set([
						*self.EXTRACTORS_ALWAYS,
						*(meta_extractors or f_snapshot_info.keys())
					]),
					return_error=True,
				)
				f_snapshot_info = {k: v for k, v in f_snapshot_info.items() if k == "error" or k in f_info}
				if f_info == f_snapshot_info:
					files_matching[fn_snapshot] = sorted(f_info.keys())
				else:
					files_changed[fn_snapshot] = {
						"old": f_snapshot_info,
						"new": f_info
					}
			else:
				files_missing.append(fn_snapshot)
			num_files_processed += 1
		self._set_status_general(None)
		if files_input:
			files_new.extend(files_input)

		assert num_files_processed == len(files_matching) + len(files_changed) + len(files_missing)
		self._log.info(progress_report_fmt.format(
			num_files_processed,
			len(files_matching),
			len(files_changed),
			len(files_missing),
			len(files_new)
		))
		return (files_matching, files_changed, files_missing, files_new)

	def _ensure_snapshot_folder(self, path):
		path = pathlib.Path(path)
		info_path = path / "info.json"
		try:
			if not os.path.exists(path) or not os.listdir(path):
				os.makedirs(path, exist_ok=True)
				self.write_json_file(info_path, {"version": 3})
			else:
				info = self.read_json_file(info_path)
				if info["version"] != 3:
					raise RuntimeError("unsupported version")
		except Exception as e:
			msg = "needs an empty or new folder or existing snapshot folder"
			raise ValueError(msg + " - " + str(e)) from e

		assert path.exists() and path.is_dir()
		return path

	def _traverse(self, folder):
		folder = os.fspath(folder)
		self._log.info("Traversing the folder recursively %r.", folder)
		result = []
		if not folder.endswith(os.path.sep):
			folder += os.path.sep
		for dirpath, dirnames, filenames in os.walk(folder):
			self._set_status_general(dirpath)
			for fn in filenames:
				path = os.path.join(dirpath, fn)
				assert path.startswith(folder)
				path = path[len(folder):]
				result.append(path)
		self._set_status_general(None)
		self._log.info("Sorting the file list.")
		result.sort()
		self._log.info("Found %s files.", "{:,}".format(len(result)))
		return result

	async def load_snapshot_meta(self):
		info_file_path = self._snapshot_path / "info.json"

		self._log.info("Loading the snapshot info from %r", os.fspath(info_file_path))

		if not self._snapshot_path.exists() or not info_file_path.exists():
			return None

		info = self.read_json_file(info_file_path)
		files_meta = info.get("files", None)
		if files_meta is None:
			return None
		file_list_path = info_file_path.parent / files_meta["path"]
		files_fileinfo = files_meta["content"]
		if files_fileinfo != await self.file_info(file_list_path, meta_extractors=list(files_fileinfo.keys())):
			raise ValueError("snapshot dir is corrupted")
		filename_hash_algo = files_meta["name_hash_algo"]

		self._log.info("Loading file list from %r.", os.fspath(file_list_path))
		file_list = self.read_json_file(file_list_path)
		self._log.info("Loaded %s files.", "{:,}".format(len(file_list)))

		return (file_list, filename_hash_algo)

	async def write_snapshot_meta(self, file_list, *, filename_hash_algo, filename_list_hash_algo):
		info_file_path = self._snapshot_path / "info.json"
		file_list_path = info_file_path.parent / "files.json"

		self._log.info("Writing the list of files to %r.", os.fspath(file_list_path))
		self.write_json_file(file_list_path, file_list)

		self._log.info("Updating %r", os.fspath(info_file_path))
		info = self.read_json_file(info_file_path)
		info["files"] = {
			"path": os.fspath(file_list_path.relative_to(info_file_path.parent)),
			"name_hash_algo": filename_hash_algo,
			"content": await self.file_info(file_list_path, meta_extractors=[filename_list_hash_algo], return_error=False),
		}
		self.write_json_file(info_file_path, info)

	def read_json_file(self, path):
		with open(path, "r") as fo:
			return json.load(fo)

	def write_json_file(self, path, data):
		with open(path, "w") as fo:
			json.dump(data, fo, indent="\t")
			fo.write("\n")

	async def get_file_info_path(self, *, filename, filename_hash_algo):
		fn_hash = await self.file_name_hash(filename, filename_hash_algo)
		fn_hash_part_1 = fn_hash[:2]
		fn_hash_part_2 = fn_hash[2:]
		result = self._snapshot_path / "files" / fn_hash_part_1 / (fn_hash_part_2 + ".json")
		os.makedirs(result.parent, exist_ok=True)
		return result

	@staticmethod
	async def file_name_hash(fn, hash_algo_name):
		assert type(fn) is str
		h = hashlib.new(hash_algo_name)
		h.update(fn.encode("utf-8"))
		return h.hexdigest()

	async def file_info(self, fn, *, meta_extractors, return_error=False):
		assert meta_extractors, meta_extractors
		lstat = os.stat(fn, follow_symlinks=False)
		file_mode_type = stat.S_IFMT(lstat.st_mode)

		if file_mode_type in (stat.S_IFREG, stat.S_IFLNK):
			result = {}
			for meta_extractor in meta_extractors:
				if meta_extractor in self.EXTRACTORS_SUPPORTED_NOOP:
					pass
				elif meta_extractor in self.EXTRACTORS_SUPPORTED_STAT:
					result[meta_extractor] = getattr(lstat, meta_extractor)
				elif meta_extractor in self.EXTRACTORS_SUPPORTED_HASH:
					if file_mode_type == stat.S_IFLNK:
						result[meta_extractor] = await self.string_hash(os.readlink(fn), meta_extractor)
					else:
						result[meta_extractor] = await self.file_content_hash(fn, meta_extractor)
				else:
					raise ValueError(f"Unsupported meta extractor {meta_extractor!r}")
			return result
		else:
			error_message = f"Unsupported file type {oct(lstat.st_mode)}"
			if return_error:
				return {
					"error": error_message
				}
			else:
				raise RuntimeError(error_message)

	async def file_content_hash(self, fn, hash_algo_name):
		threshold_to_display_progress = 2
		should_display_progress = None
		start_time = time.time()
		stat = os.stat(fn)
		h = hashlib.new(hash_algo_name)
		with open(fn, "rb") as fo:
			bytes_done = 0
			while True:
				if should_display_progress is None:
					if (time.time() - start_time) > threshold_to_display_progress:
						should_display_progress = True
				if should_display_progress:
					self._set_status_hash(("[{:7.2f}%] Hashing {!r}").format(
						(10000 * bytes_done / stat.st_size) / 100.0,
						os.fspath(fn),
					))
				b = fo.read(self._chunk_size)
				if not b:
					break
				h.update(b)
				bytes_done += len(b)
			self._set_status_hash(None)
		return h.hexdigest()

	async def string_hash(self, s, hash_algo_name):
		h = hashlib.new(hash_algo_name)
		h.update(s.encode("utf-8")) #TODO Make sure that this is a stable encoding - what does git do with filenames?
		return h.hexdigest()

	def _set_status_general(self, s):
		self._status_general = self._set_status_line(self._status_general, s)
		if self._status_hash is not None:
			self._status_hash = self._set_status_line(self._status_hash, None)

	def _set_status_hash(self, s):
		if s is None and self._status_hash is None:
			return
		self._status_hash = self._set_status_line(self._status_hash, s)
