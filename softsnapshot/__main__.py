#!/usr/bin/env python

import sys, asyncio, logging, logging.config, pathlib, shutil, json, zipfile, os
import docopt
from .core import SoftSnapshot


logger = None
screen_width = shutil.get_terminal_size((None, None)).columns


async def main(*, args=None, prog=None, loop=None):
	opts = docopt.docopt(load_usage(), argv=args, options_first=False, help=True, version="0.0.0")
	assert opts.pop("--help") is False
	assert opts.pop("--version") is False
	must_update = opts.pop("--update")
	input_dir = pathlib.Path(opts.pop("--input")).resolve()
	snapshot_dir = pathlib.Path(opts.pop("--snapshot")).resolve()
	assert opts.pop("--check") is not must_update
	assert not opts, opts

	_configure_logging()

	SoftSnapshot.display = display

	ss = SoftSnapshot(snapshot_dir)
	if must_update:
		await ss.update(input_dir)
	else:
		changed, missing, new = await ss.check(input_dir)
		if changed:
			logger.info("Changed: %s", json.dumps(changed, indent="\t"))
		if missing:
			logger.info("Missing: %s", json.dumps(missing, indent="\t"))
		if new:
			logger.info("New: %s", json.dumps(list(new), indent="\t"))



def load_usage():
	usage_file_encoding = "UTF-8"
	usage_file = pathlib.Path(__file__).parent / "usage.txt"
	if usage_file.exists():
		with usage_file.open("rb") as fo:
			return fo.read().decode(usage_file_encoding)
	else:
		zipfile_path = usage_file
		while zipfile_path.parts != ():
			zipfile_path = zipfile_path.parent
			usage_file_inzip = usage_file.relative_to(zipfile_path)
			if not zipfile_path.exists():
				continue
			with zipfile.ZipFile(zipfile_path) as zf:
				with zf.open(os.fspath(usage_file_inzip), "r") as fo:
					return fo.read().decode(usage_file_encoding)
		raise RuntimeError("Failed to find usage.txt")


def display(s):
	if s is not None:
		s = s[-1 * (screen_width - 1):].ljust(screen_width) + "\r"
	else:
		s = "\r" + " " * screen_width + "\r"

	sys.stdout.write(s)
	sys.stdout.flush()


def _configure_logging():
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


def _smain(*, argv=None):
	if sys.platform == "win32":
		loop = asyncio.ProactorEventLoop()
		asyncio.set_event_loop(loop)
	else:
		loop = asyncio.get_event_loop()
	loop.run_until_complete(main(args=argv[1:], prog=argv[0], loop=loop))


def _ssmain():
	try:
		sys.exit(_smain(argv=sys.argv))
	except KeyboardInterrupt:
		print(file=sys.stderr)



if __name__ == "__main__":
	_ssmain()
