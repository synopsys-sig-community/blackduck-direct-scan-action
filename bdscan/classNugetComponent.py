import re
import os
import tempfile

from bdscan import globals, classComponent

# from lxml import etree
import xml.etree.ElementTree as ET


class MyTreeBuilder(ET.TreeBuilder):
    def comment(self, data):
        self.start(ET.Comment, {})
        self.data(data)
        self.end(ET.Comment)


class NugetComponent(classComponent.Component):
    def __init__(self, compid, name, version, ns):
        super().__init__(compid, name, version, ns)
        self.pm = 'nuget'
        self.pms = ['nuget']

    def get_http_name(self):
        bdio_name = f"http:" + re.sub(":", "/", self.compid)
        return bdio_name

    @staticmethod
    def normalise_dep(dep):
        #
        # Replace / with :
        if dep.find('http:') == 0:
            dep = dep.replace('http:', '').replace('nuget/', 'nuget:')
        return dep

    def prepare_upgrade(self, index):
        proj_contents = ''
        if not os.path.isfile('test.csproj'):
            proj_contents = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>netcoreapp3.1</TargetFramework>
  </PropertyGroup>
'''

        proj_contents += f'''  <ItemGroup>
    <PackageReference Include="{self.name}" Version="{self.potentialupgrades[index]}" />
  </ItemGroup>
'''
        try:
            with open('test.csproj', "a") as fp:
                fp.write(proj_contents)
        except Exception as e:
            print(e)
            return False
        return True

    def get_projfile_linenum(self, filename):
        ext = '.' + filename.split('.')[-1]
        if ext not in globals.pkg_exts:
            return -1
        namestring = f'Include="{self.name}"'.lower()
        try:
            with open(filename, 'r') as f:
                for (i, line) in enumerate(f):
                    if namestring in line.lower():
                        return i
        except Exception as e:
            return -1
        return -1

    @staticmethod
    def finalise_upgrade():
        try:
            with open('test.csproj', "a") as fp:
                fp.write('</Project>\n')
        except Exception as e:
            print(e)
        return

    # Todo: Add do_upgrade_dependency()
    def do_upgrade_dependency(self):
        files_to_patch = dict()

        # dirname = tempfile.TemporaryDirectory()
        tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + self.name + "-" + self.version)

        for package_file in self.projfiles:
            # Todo: Manage sub-folders

            try:
                # tree = etree.parse(package_file)
                # root = tree.getroot()
                #
                # namespaces = {'ns': 'http://schemas.microsoft.com/developer/msbuild/2003'}
                # myval = tree.xpath(f'.//PackageReference[@Include="{self.name}"][@Version="{self.version}"]',
                #                    namespaces=namespaces)
                # if myval is not None:
                #     myval[0].attrib['Version'] = self.goodupgrade
                #
                # # Change into sub-folder for packagefile
                # subtempdir = os.path.dirname(package_file)
                # os.makedirs(os.path.join(tempdirname, subtempdir), exist_ok=True)
                #
                # xmlstr = ET.tostring(root, encoding='utf8', method='xml')
                # with open(os.path.join(tempdirname, package_file), "wb") as fp:
                #     fp.write(xmlstr)
                compstring = f'<PackageReference Include="{self.name}" Version="{self.version}"'
                new_pkg_contents = ''

                with open(package_file, 'r') as fi:
                    foundcomp = False
                    for line in fi:
                        if compstring in line:
                            foundcomp = True
                            new_pkg_contents += \
                                f'<PackageReference Include="{self.name}" Version="{self.goodupgrade}"\n'
                        else:
                            new_pkg_contents += line

                # Create sub-folder for packagefile
                subtempdir = os.path.dirname(package_file)
                os.makedirs(os.path.join(tempdirname, subtempdir), exist_ok=True)

                with open(os.path.join(tempdirname, package_file), 'w') as fo:
                    fo.write(new_pkg_contents)

            except Exception as e:
                print(f"BD-Scan-Action: ERROR: Unable to update {package_file} - {e}")
            else:
                print(f"BD-Scan-Action: INFO: Updated Nuget component in: {package_file}")
                if foundcomp:
                    files_to_patch[package_file] = os.path.join(tempdirname, package_file)

        return files_to_patch

    @staticmethod
    def supports_direct_upgrades():
        return True
