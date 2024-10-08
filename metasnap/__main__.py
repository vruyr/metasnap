#!/usr/bin/env python

import sys, asyncio, logging, logging.config, pathlib, shutil, json, zipfile, os, collections, functools, textwrap, ast
from collections.abc import Iterable, Sequence
from typing import IO, TextIO, TypeAlias
import docopt
from .core import MetadataExtractor, Metasnap, SnapshotCheckReport, StatusLineId, StatusLineContent, StatusLineSetter


logger: logging.Logger | None = None
screen_width = shutil.get_terminal_size((0, 0)).columns


StatusLines: TypeAlias = collections.OrderedDict[StatusLineId, str]


async def main(*,
	args: Iterable[str],
	prog: str,
	loop: asyncio.AbstractEventLoop,
) -> None:
	opts = docopt.docopt(
		load_usage(
			list_of_always_included_extractors=Metasnap.EXTRACTORS_ALWAYS,
			list_of_extractors=Metasnap.all_supported_extractors(),
		),
		argv=args,
		options_first=False,
		help=True,
		version="0.0.0"
	)
	assert opts.pop("--help") is False
	assert opts.pop("--version") is False
	must_update = opts.pop("--update")
	input_dir = pathlib.Path(opts.pop("--input")).resolve()
	snapshot_dir = pathlib.Path(opts.pop("--snapshot")).resolve()
	st_mode_mask = ast.literal_eval(opts.pop("--umask", None) or "0") & 0o0777
	meta_extractors = opts.pop("--extractor")

	report_file_path = opts.pop("--check")
	if must_update:
		assert report_file_path is None
	assert not opts, opts

	_configure_logging()

	assert logger, (logger,)

	status_lines: StatusLines = collections.OrderedDict()
	status_line_setter: StatusLineSetter = functools.partial(set_status_line,
		status_lines=status_lines,
		max_width=screen_width,
		tty_fo=sys.stdout,
	)
	#TODO If anything is written to the same tty_fo without clearing the status first - the output will be messed up.

	if not must_update:
		logger.info("Report will be written to %s", repr(report_file_path) if report_file_path != "-" else "stdout")

	ss = Metasnap(snapshot_dir, status_line_setter=status_line_setter, st_mode_mask=st_mode_mask)

	if must_update:
		await ss.update(input_dir, meta_extractors=meta_extractors)
	else:
		changed, missing, new = await ss.check(input_dir, meta_extractors=meta_extractors)

		if report_file_path == "-":
			write_report(sys.stdout, changed, missing, new)
		else:
			with open(report_file_path, "w") as fo:
				write_report(fo, changed, missing, new)


def write_report(fo: TextIO, changed: SnapshotCheckReport, missing: SnapshotCheckReport, new: SnapshotCheckReport):
	report = {
		**changed,
		**missing,
		**new,
	}
	json.dump(report, fo, sort_keys=True, indent="\t")
	fo.write("\n")


def set_status_line(status_id: StatusLineId, text: StatusLineContent, *, status_lines: StatusLines, max_width: int, tty_fo: TextIO):
	assert status_id is not None or text is not None

	cursor = len(status_lines)

	if status_id is None:
		status_id = object()
		status_lines[status_id] = ""

	status_line_ids = list(status_lines.keys())
	status_id_index = status_line_ids.index(status_id)
	num_lines_back = cursor - status_id_index
	assert num_lines_back >= 0

	control = ""

	if num_lines_back:
		control += f"\x1b[{num_lines_back}F"

	if text is not None:
		status_lines[status_id] = text
		show_begin = status_id_index
		show_end = status_id_index + 1
		num_lines_forward = num_lines_back - 1
	else:
		show_begin = status_id_index + 1
		show_end = len(status_line_ids)
		num_lines_forward = 0
		del status_lines[status_id]
		status_id = None

	for i in status_line_ids[show_begin:show_end]:
		text = status_lines[i]
		text = text[-1 * (max_width - 1):].ljust(max_width)
		control += f"{text}\x1b[0K\n"
	if num_lines_forward > 0:
		control += f"\x1b[{num_lines_forward}E"

	control += "\x1b[0K"

	tty_fo.write(control)
	tty_fo.flush()

	return status_id


def load_usage(*,
	width: int = 70,
	list_of_always_included_extractors: Iterable[MetadataExtractor],
	list_of_extractors: Iterable[MetadataExtractor],
):
	usage_file_encoding = "UTF-8"
	usage_file = pathlib.Path(__file__).parent / "usage.txt"
	result = None
	fo: IO[bytes]
	if usage_file.exists():
		with usage_file.open("rb") as fo:
			result = fo.read().decode(usage_file_encoding)
	else:
		zipfile_path = usage_file
		while zipfile_path.parts != ():
			zipfile_path = zipfile_path.parent
			usage_file_inzip = usage_file.relative_to(zipfile_path)
			if not zipfile_path.exists():
				continue
			with zipfile.ZipFile(zipfile_path) as zf:
				with zf.open(os.fspath(usage_file_inzip), "r") as fo:
					result = fo.read().decode(usage_file_encoding)
					break
		else:
			raise RuntimeError("Failed to find usage.txt")

	def format_list(l: Iterable[str]):
		#TODO Do not assume usage text is indented with two spaces.
		return "\n  ".join(textwrap.wrap(
			", ".join(l),
			width=width,
		))

	return result.format(
		list_of_always_included_extractors=format_list(list_of_always_included_extractors),
		list_of_extractors=format_list(list_of_extractors),
	)


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


def _smain(*, argv: Sequence[str]):
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
