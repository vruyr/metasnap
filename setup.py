from setuptools import setup


# rm -rf _build && python3 -m pip install --target=_build/stuff . && python3 -m zipapp -o _build/softsnapshot.pyz --main softsnapshot.__main__:_ssmain -p "/usr/bin/env python3" _build/stuff


setup(
	name="softsnapshot",
	version="0.0.0",
	description="",
	url="",
	license="UNLICENSED",
	packages=[
		"softsnapshot"
	],
	package_data={
		"": [
			"usage.txt"
		],
	},
	install_requires=[
		"docopt>=0.6.2,<0.7.0",
	]
)
