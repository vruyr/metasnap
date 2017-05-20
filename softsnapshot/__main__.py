#!/usr/bin/env python
import sys; assert sys.version_info[:2] in [(3, 6)]
import argparse, asyncio, os, logging, logging.config, json, hashlib, time


logger = None
screen_width = 158
chunk_size = 512 * 2014
hash_algo = "sha1"


async def main(*, argv=None, loop=None):
	opts = _parse_args(argv=argv)
	_configure_logging(opts)
	#TODO Verify that the output folder is for the same input folder

	files = None
	file_list_path = os.path.join(opts.output_path, "files.json")
	if os.path.exists(file_list_path):
		logger.info("Loading file list from %r.", file_list_path)
		files = await load_json_file(file_list_path)
		logger.info("Loaded %s files.", "{:,}".format(len(files)))
	else:
		logger.info("Traversing the folder recursively %r.", opts.input_path)
		files = traverse(opts.input_path)
		files.sort()
		logger.info("Found %s files.", "{:,}".format(len(files)))
		logger.info("Writing the list of files to %r.", file_list_path)
		await write_json_file(file_list_path, files)

	os.makedirs(os.path.join(opts.output_path, "files"), exist_ok=True)

	logger.info("Processing files.")

	num_files = len(files)
	num_files_processed = 0
	num_files_skipped = 0
	for fn in files:
		display_progress(
			(10000 * num_files_processed / num_files) / 100.0,
			"{:7.2f}% of files processed",
		)
		fn_hash = await file_name_hash(fn)
		f_info_path = os.path.join(opts.output_path, "files", fn_hash + ".json")
		if not os.path.exists(f_info_path):
			f_info = await file_info(os.path.join(opts.input_path, fn))
			await write_json_file(f_info_path, f_info)
		else:
			num_files_skipped += 1
		num_files_processed += 1
	display(None)
	logger.info("%s files processed of which %s skipped.",
		"{:,}".format(num_files_processed),
		"{:,}".format(num_files_skipped),
	)


async def file_info(fn, hash_name=hash_algo):
	if os.path.islink(fn):
		return {
			"symlink": os.readlink(fn)
		}
	elif os.path.isfile(fn):
		return {
			hash_name: await file_content_hash(fn, hash_name)
		}
	else:
		logger.error("Unsupported non-regular file: %r", fn)
		return None


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
					(10000 * bytes_done / stat.st_size) / 100.0,
					"{:7.2f}%% of %r hashed" % fn,
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
	return result


display_progress_last = None
def display_progress(progress, fmt="{}"):
	if progress == display_progress_last:
		return
	display(fmt.format(progress))


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
		type=_ensure_our_folder,
		required=True,
		help="",
	)
	opts = parser.parse_args((argv[1:] if argv is not None else None))
	return opts


def _ensure_existing_folder(x):
	try:
		with os.scandir(x):
			pass
	except Exception as e:
		msg = "needs to be an existing and accessible folder"
		raise argparse.ArgumentTypeError(msg + " - " + str(e)) from e
	return x


def _ensure_our_folder(x):
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
		msg = "needs a new folder or existing admin folder"
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
