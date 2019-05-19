from setuptools import setup, find_packages


# rm -rf _build && python3 -m pip install --target=_build/stuff . && python3 -m zipapp -o _build/metasnap.pyz --main metasnap.__main__:_ssmain -p "/usr/bin/env python3" _build/stuff


setup(
	name="metasnap",
	version="0.0.0",
	description="",
	url="",
	license="UNLICENSED",
	packages=find_packages(
		".",
		include=[
			"metasnap", "metasnap.*",
		],
	),
	entry_points={
		"console_scripts": [
			"metasnap = metasnap.__main__:_ssmain",
		],
	},
	package_data={
		"": [
			"usage.txt"
		],
	},
	install_requires=[
		"docopt>=0.6.2,<0.7.0",
	]
)
