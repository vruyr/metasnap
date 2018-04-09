#!/usr/bin/env python

import sys, argparse, asyncio, os, logging, logging.config, json, hashlib, time, pathlib


logger = None
screen_width = 158
chunk_size = 512 * 2014
hash_algo = "sha1"


async def main(*, argv=None, loop=None):
	opts = _parse_args(argv=argv)
	_configure_logging(opts)

	files_input = traverse(opts.input_path)

	if opts.update:
		await write_files_list(opts.output_path, files_input)

		os.makedirs(os.path.join(opts.output_path, "files"), exist_ok=True)

		logger.info("Hashing files.")

		num_files = len(files_input)
		num_files_processed = 0
		num_files_skipped = 0
		for fn in files_input:
			display_progress(
				"[{:7.2f}%] {} files processed, of which {} skipped.",
				(10000 * num_files_processed / num_files) / 100.0,
				num_files_processed,
				num_files_skipped,
			)
			f_info_path = await get_file_info_path(opts.output_path, fn)
			if not os.path.exists(f_info_path):
				f_path = os.path.join(opts.input_path, fn)
				f_info = await file_info(f_path, hash_algo, return_error=True)
				if f_info.get("error", None):
					logger.info("Failed to hash file %r - %s", f_path, f_info.get("error"))
				else:
					await write_json_file(f_info_path, f_info)
			else:
				num_files_skipped += 1
			num_files_processed += 1
		display(None)
		logger.info("%s files processed of which %s skipped.",
			"{:,}".format(num_files_processed),
			"{:,}".format(num_files_skipped),
		)
	else:
		files_matching = []
		files_changed = {}
		files_missing = []
		files_new = []

		files_snapshot = await load_files_list(opts.output_path)
		files_snapshot = set(files_snapshot)
		files_input = set(files_input)
		num_files = len(files_snapshot)
		num_files_processed = 0
		progress_report_fmt = "Processed {:,} files of which {:,} were matching, {:,} has changed, {:,} were missing, and {:,} are new."
		while files_snapshot:
			display_progress(
				"[{:7.2f}%] " + progress_report_fmt,
				(10000 * num_files_processed / num_files) / 100.0,
				num_files_processed,
				len(files_matching),
				len(files_changed),
				len(files_missing),
				len(files_new)
			)
			fn_snapshot = files_snapshot.pop()
			if fn_snapshot in files_input:
				files_input.remove(fn_snapshot)
				f_snapshot_info = await load_json_file(await get_file_info_path(opts.output_path, fn_snapshot))
				f_info = await file_info(os.path.join(opts.input_path, fn_snapshot), hash_algo, return_error=True)
				if f_snapshot_info == f_info:
					files_matching.append(fn_snapshot)
				else:
					files_changed[fn_snapshot] = {
						"old": f_snapshot_info,
						"new": f_info
					}
			else:
				files_missing.append(fn_snapshot)
			num_files_processed += 1
		display(None)
		if files_input:
			files_new.extend(files_input)

		assert num_files_processed == (
			len(files_matching) + len(files_changed) + len(files_missing) + len(files_new)
		)
		logger.info(progress_report_fmt.format(
			num_files_processed,
			len(files_matching),
			len(files_changed),
			len(files_missing),
			len(files_input)
		))


async def get_file_info_path(snapshot_folder, filename):
	fn_hash = await file_name_hash(filename)
	return os.path.join(snapshot_folder, "files", fn_hash + ".json")


async def load_files_list(snapshot_folder):
	snapshot_folder = pathlib.Path(snapshot_folder)
	info_file_path = snapshot_folder / "info.json"

	logger.info("Loading the snapshot info from %r", os.fspath(info_file_path))

	if not snapshot_folder.exists() or not info_file_path.exists():
		return None
	info = await load_json_file(info_file_path)
	files_fileinfo = info.get("files", None)
	if files_fileinfo is None:
		return None

	file_list_path = snapshot_folder / "files.json"
	if files_fileinfo != await file_info(file_list_path, hash_algo, return_error=False):
		raise ValueError("snapshot dir is corrupted")

	logger.info("Loading file list from %r.", os.fspath(file_list_path))
	file_list = await load_json_file(file_list_path)
	logger.info("Loaded %s files.", "{:,}".format(len(file_list)))

	return file_list


async def write_files_list(snapshot_folder, file_list):
	snapshot_folder = pathlib.Path(snapshot_folder)
	info_file_path = snapshot_folder / "info.json"
	file_list_path = snapshot_folder / "files.json"

	logger.info("Writing the list of files to %r.", os.fspath(file_list_path))
	await write_json_file(file_list_path, file_list)

	logger.info("Updating %r", os.fspath(info_file_path))
	info = await load_json_file(info_file_path)
	info["files"] = await file_info(file_list_path, hash_algo, return_error=False)
	await write_json_file(info_file_path, info)


async def file_info(fn, hash_name=hash_algo, *, return_error=False):
	if os.path.islink(fn):
		return {
			"symlink": os.readlink(fn)
		}
	elif os.path.isfile(fn):
		return {
			hash_name: await file_content_hash(fn, hash_name)
		}
	else:
		error_message = "unsupported non-regular file"
		if return_error:
			return {
				"error": error_message
			}
		else:
			raise RuntimeError(error_message)


async def file_name_hash(fn, hash_name=hash_algo):
	assert type(fn) is str
	h = hashlib.new(hash_name)
	h.update(fn.encode("utf-8"))
	return h.hexdigest()


async def file_content_hash(fn, hash_name=hash_algo):
	threshold_to_display_progress = 2
	should_display_progress = None
	start_time = time.time()
	stat = os.stat(fn)
	h = hashlib.new(hash_name)
	with open(fn, "rb") as fo:
		bytes_done = 0
		while True:
			if should_display_progress is None:
				if (time.time() - start_time) > threshold_to_display_progress:
					should_display_progress = True
			if should_display_progress:
				display_progress(
					"{:7.2f}%% of %r hashed" % fn,
					(10000 * bytes_done / stat.st_size) / 100.0,
				)
			b = fo.read(chunk_size)
			if not b:
				break
			h.update(b)
			bytes_done += len(b)
		if should_display_progress:
			display(None)
	return h.hexdigest()



async def write_json_file(path, data):
	with open(path, "w") as fo:
		json.dump(data, fo, indent="\t")
		fo.write("\n")


async def load_json_file(path):
	with open(path, "r") as fo:
		return json.load(fo)


def traverse(folder):
	logger.info("Traversing the folder recursively %r.", folder)
	result = []
	if not folder.endswith(os.path.sep):
		folder += os.path.sep
	for dirpath, dirnames, filenames in os.walk(folder):
		display(dirpath)
		for fn in filenames:
			path = os.path.join(dirpath, fn)
			assert path.startswith(folder)
			path = path[len(folder):]
			result.append(path)
	display(None)
	logger.info("Sorting the file list.")
	result.sort()
	logger.info("Found %s files.", "{:,}".format(len(result)))
	return result


def display_progress(fmt, *args, **kwargs):
	display(fmt.format(*args, **kwargs))


def display(s):
	if s is not None:
		s = s[-1 * (screen_width - 1):].ljust(screen_width) + "\r"
	else:
		s = "\r" + " " * screen_width + "\r"

	sys.stdout.write(s)
	sys.stdout.flush()


def _configure_logging(opts):
	logging.config.dictConfig({
		"version": 1,
		"handlers": {
			"console": {
				"class": "logging.StreamHandler",
				"formatter": "console",
				"level": "INFO",
				"stream": "ext://sys.stdout",
			},
		},
		"formatters": {
			"console": {
				"class": "logging.Formatter",
				"format": "[%(asctime)s] %(message)s",
				"datefmt": '%Y-%m-%d %H:%M:%S %z'
			},
		},
		"level": "INFO",
		"root": {
			"level": "INFO",
			"handlers": ["console"]
		},
	})
	global logger
	logger = logging.getLogger(__name__)


def _parse_args(argv=None):
	parser = argparse.ArgumentParser(
		prog=(argv[0] if argv is not None else None),
		description=None,
		epilog=None
	)
	parser.add_argument(
		"--input", "-i",
		dest="input_path",
		action="store",
		metavar="DIR_PATH",
		type=_ensure_existing_folder,
		required=True,
		help="",
	)
	parser.add_argument(
		"--output", "-o",
		dest="output_path",
		action="store",
		metavar="DIR_PATH",
		type=_ensure_snapshot_folder,
		required=True,
		help="",
	)
	parser.add_argument(
		"--update", "-u",
		dest="update",
		action="store_true",
		default=None,
		help="create or update the snapshot",
	)
	parser.add_argument(
		"--check", "-c",
		dest="update",
		action="store_false",
		default=None,
		help="check if the snapshot matches input folder",
	)
	opts = parser.parse_args((argv[1:] if argv is not None else None))
	if opts.update is None:
		parser.error("either --update or --check should be passed")
	return opts


def _ensure_existing_folder(x):
	try:
		with os.scandir(x):
			pass
	except Exception as e:
		msg = "needs to be an existing and accessible folder"
		raise argparse.ArgumentTypeError(msg + " - " + str(e)) from e
	return x


def _ensure_snapshot_folder(x):
	info_path = os.path.join(x, "info.json")
	try:
		if not os.path.exists(x) or not os.listdir(x):
			os.makedirs(x, exist_ok=True)
			with open(info_path, "w") as fo:
				json.dump({"version": 1}, fo, indent="\t")
				fo.write("\n")
		else:
			with open(info_path, "r") as fo:
				info = json.load(fo)
				if info["version"] != 1:
					raise RuntimeError("unsupported version")
	except Exception as e:
		msg = "needs an empty or new folder or existing snapshot folder"
		raise argparse.ArgumentTypeError(msg + " - " + str(e)) from e
	return x


def _smain(*, argv=None):
	if sys.platform == "win32":
		loop = asyncio.ProactorEventLoop()
		asyncio.set_event_loop(loop)
	else:
		loop = asyncio.get_event_loop()
	loop.run_until_complete(main(argv=argv, loop=loop))


if __name__ == "__main__":
	try:
		sys.exit(_smain())
	except KeyboardInterrupt:
		print(file=sys.stderr)
