import re
import os
import tempfile
# import semver
import xml.etree.ElementTree as ET

from bdscan import globals, classComponent


class MyTreeBuilder(ET.TreeBuilder):
    def comment(self, data):
        self.start(ET.Comment, {})
        self.data(data)
        self.end(ET.Comment)


class MavenComponent(classComponent.Component):
    def __init__(self, compid, org, name, version, ns):
        super().__init__(compid, name, version, ns)
        self.org = org
        self.pm = 'maven'
        self.pms = ['maven', 'gradle']

    def get_http_name(self):
        bdio_name = "http:" + re.sub(":", "/", self.compid)
        return bdio_name

    def get_projfile(self, entry, allpoms):
        import urllib.parse
        foundpom = ''
        folderarr = entry.split('/')
        if len(folderarr) < 3:
            return ''

        # folder = folderarr[-2]
        folder = urllib.parse.unquote(folderarr[-2])
        farr = folder.split(os.path.sep)
        # 'http:maven/com.blackducksoftware.test/example-maven-travis/0.1.0-SNAPSHOT/example-maven-travis/maven'
        # 'http:maven/com.blackducksoftware.test/example-maven-travis/0.1.0-SNAPSHOT/copilot-maven%2Fexample-maven-travis/maven'
        if len(farr) > 1:
            topfolder = farr[-2]
        else:
            topfolder = ''
        for pom in allpoms:
            arr = pom.split(os.path.sep)
            if len(arr) >= 2 and arr[-2] == topfolder:
                if os.path.isfile(pom):
                    foundpom = pom
                    break
            elif topfolder == '':
                foundpom = pom
                break
        return foundpom

    @staticmethod
    def normalise_dep(dep):
        #
        # Replace / with :
        if dep.find('http:') == 0:
            dep = dep.replace('http:', '')
        return dep.replace('/', ':')

    def check_ver_origin(self, ver):
        if len(self.origins) > 0 and ver in self.origins.keys():
            for over in self.origins[ver]:
                if 'originName' in over and 'originId' in over and over['originName'] == self.ns:
                    # 'org.springframework:spring-aop:3.2.10.RELEASE'
                    corg, cname, cver = self.parse_compid(over['originId'])
                    # a_over = over['originId'].split(':')
                    if corg == self.org and cname == self.name:
                        return True
        return False

    def prepare_upgrade(self, upgrade_index):
        if len(self.potentialupgrades) < upgrade_index:
            return False
        upgrade_version = self.potentialupgrades[upgrade_index]

        pom_contents = ''
        if not os.path.isfile('pom.xml'):
            pom_contents = f'''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>sec</groupId>
    <artifactId>test</artifactId>
    <version>1.0.0</version>
    <packaging>pom</packaging>

    <dependencies>
'''
        # arr = self.compid.split(':')
        # forge = arr[0]
        groupid = self.org
        artifactid = self.name
        pom_contents += f'''    <dependency>
        <groupId>{groupid}</groupId>
        <artifactId>{artifactid}</artifactId>
        <version>{upgrade_version}</version>
    </dependency>
'''
        try:
            with open('pom.xml', "a") as fp:
                fp.write(pom_contents)
        except Exception as e:
            print(e)
            return False
        return True

    def get_projfile_linenum(self, filename):
        if not filename.endswith('pom.xml'):
            return -1

        def getline(comp, ver, filename):
            compstring = f"<artifactId>{comp}</artifactId>".lower()
            verstring = f"<version>{ver}</version>".lower()
            try:
                with open(filename, 'r') as f:
                    foundcomp = False
                    for (i, line) in enumerate(f):
                        if compstring in line.lower():
                            foundcomp = True
                        if foundcomp and (ver == '' or verstring in line.lower()):
                            return i
            except Exception as e:
                pass
            return -1

        # parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

        ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
        ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

        tree = ET.parse(filename, parser=ET.XMLParser(target=MyTreeBuilder()))
        root = tree.getroot()

        nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

        for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
            groupId = dep.find('m:groupId', nsmap).text
            artifactId = dep.find('m:artifactId', nsmap).text
            version = ''
            verentry = dep.find('m:version', nsmap)
            if verentry is not None:
                version = verentry.text

            if artifactId == self.name and (version == '' or "${" in version):
                return getline(self.name, '', filename)

            if artifactId == self.name and version == self.version:
                return getline(self.name, self.version, filename)

        return -1

    def do_upgrade_dependency(self):
        files_to_patch = dict()

        # dirname = tempfile.TemporaryDirectory()
        tempdirname = tempfile.mkdtemp(prefix="snps-patch-" + self.name + "-" + self.version)

        for package_file in self.projfiles:
            # dir = os.path.sep.join(package_file.split(os.path.sep)[:-1])
            parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))

            ET.register_namespace('', "http://maven.apache.org/POM/4.0.0")
            ET.register_namespace('xsi', "http://www.w3.org/2001/XMLSchema-instance")

            tree = ET.parse(package_file, parser=ET.XMLParser(target=MyTreeBuilder()))
            root = tree.getroot()

            nsmap = {'m': 'http://maven.apache.org/POM/4.0.0'}

            # globals.printdebug(f"DEBUG: Search for maven dependency {component_name}@{component_version}")

            for dep in root.findall('.//m:dependencies/m:dependency', nsmap):
                groupId = dep.find('m:groupId', nsmap).text
                artifactId = dep.find('m:artifactId', nsmap).text
                verentry = dep.find('m:version', nsmap)
                if artifactId == self.name:
                    if verentry is not None:
                        version = verentry.text
                        globals.printdebug(
                            f"DEBUG:   Found GroupId={groupId} ArtifactId={artifactId} Version={version}")
                        verentry.text = self.goodupgrade
                        break
                    else:
                        # ToDo: Need to add version tag as it does not exist
                        new = ET.Element('version')
                        new.text = self.goodupgrade
                        dep.append(new)
                        break

            # Change into sub-folder for packagefile
            subtempdir = os.path.dirname(package_file)
            os.makedirs(os.path.join(tempdirname, subtempdir), exist_ok=True)

            xmlstr = ET.tostring(root, encoding='UTF-8', method='xml')
            with open(os.path.join(tempdirname, package_file), "wb") as fp:
                fp.write(xmlstr)

            print(f"BD-Scan-Action: INFO: Updated Maven component in: {os.path.join(tempdirname, package_file)}")

            files_to_patch[package_file] = os.path.join(tempdirname, package_file)

        return files_to_patch

    @staticmethod
    def finalise_upgrade():
        try:
            with open('pom.xml', "a") as fp:
                fp.write('''    </dependencies>
</project>
''')
            # os.system('cat pom.xml')
        except Exception as e:
            print(e)
        return

    @staticmethod
    def parse_compid(compid):
        arr = re.split('[:/]', compid)
        if len(arr) == 4:
            return arr[1], arr[2], arr[3]
        else:
            return arr[0], arr[1], arr[2]

    @staticmethod
    def supports_direct_upgrades():
        return True
