#!/usr/bin/env python

import sys, argparse, asyncio, importlib.metadata, logging, logging.config, pathlib, shutil, json, os, collections, functools, ast, textwrap
from collections.abc import Sequence
from typing import TextIO, TypeAlias
from .core import Metasnap, SnapshotCheckReport, StatusLineId, StatusLineContent, StatusLineSetter


logger: logging.Logger | None = None
screen_width = shutil.get_terminal_size((0, 0)).columns


StatusLines: TypeAlias = collections.OrderedDict[StatusLineId, str]


def parse_args(*, args, prog):
	parser = argparse.ArgumentParser(
		prog=prog,
		description="Create and verify file metadata snapshots.",
		epilog=textwrap.dedent("""\
			always included extractors:
			  {always}

			supported extractors:
			  {supported}
		""").format(
			always=", ".join(Metasnap.EXTRACTORS_ALWAYS),
			supported=", ".join(Metasnap.all_supported_extractors()),
		),
		formatter_class=argparse.RawDescriptionHelpFormatter,
		add_help=False,
	)

	parser.add_argument("--help", "-h",
		action="help",
		help="Show help message and exit.")
	parser.add_argument("--version", action="version", version=importlib.metadata.version("metasnap"))
	parser.add_argument("--input", "-i", required=True, metavar="DIR_PATH",
		help="Path to the input folder.")
	parser.add_argument("--snapshot", "-s", required=True, metavar="DIR_PATH",
		help="Path to the snapshot folder.")
	parser.add_argument("--extractor", "-e", action="append", default=[], metavar="NAME",
		help="Name of a metadata extractor to include. Can be specified multiple times.")
	parser.add_argument("--umask", metavar="MODE", default="0",
		help="st_mode = st_mode & ~umask. Similar to umask(2). "
			"Use 0o077 to ignore all permissions for group and other. "
			"Use 0o177 to also ignore the execute bit for the file owner.")

	mode = parser.add_mutually_exclusive_group(required=True)

	mode.add_argument("--update", "-u", action="store_true", dest="must_update",
		help="Create or update the snapshot for the input folder.")
	mode.add_argument("--check", "-c", metavar="REPORT_FILE_PATH",
		help="Check if the snapshot matches the input folder. "
			"Results will be written to REPORT_FILE_PATH (or stdout if '-').")
	opts = parser.parse_args(args)
	return vars(opts)


async def main(*,
	input,
	snapshot,
	must_update,
	check,
	extractor,
	umask,
) -> None:
	input_dir = pathlib.Path(input).resolve()
	snapshot_dir = pathlib.Path(snapshot).resolve()
	st_mode_mask = ast.literal_eval(umask) & 0o0777
	meta_extractors = extractor
	report_file_path = check

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
	opts = parse_args(args=argv[1:], prog=argv[0])
	asyncio.run(main(**opts))


def _ssmain():
	try:
		sys.exit(_smain(argv=sys.argv))
	except KeyboardInterrupt:
		print(file=sys.stderr)



if __name__ == "__main__":
	_ssmain()
