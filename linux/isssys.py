### System Information Libraries ###
import socket
import platform

### SystemUpdates Libraries ###
import os

#### This need to be removed so it will only be loaded when running Debian/Ubuntu
import apt, apt_pkg
import subprocess
SYNAPTIC_PINFILE = "/var/lib/synaptic/preferences"
DISTRO = subprocess.check_output(["lsb_release", "-c", "-s"],
                                 universal_newlines=True).strip()


class SystemInformation(object):
    """client_infoNonermation
    We will collect all information about your system that is nessecary
    for IssBot to operate and collect valueble data for our Machine Learning
    to operate as good as possible.
    """

    def __init__(self):
        super(SystemInformation, self).__init__()
        self.name = None

    def get_ip_address(self, connect="8.8.8.8"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((connect, 80))
        return(s.getsockname()[0])

    def client_information(self):
        client = {}

        uname = platform.uname()
        client['hostname'] = uname[1]
        client['architecture'] = uname[4]
        client['fqdn'] = socket.getfqdn()
        client['kernel'] = uname[2]
        client['operating_system'] = uname[3]
        client['ipv4'] = self.get_ip_address(connect="8.8.8.8")

class SystemUpdates(object):
    """
    In this class can you identify all system updates and process each update
    """

    def __init__(self, package_manager):
        super(SystemUpdates, self).__init__()
        self.package_manager = package_manager

    def saveDistUpgrade(self,cache,depcache):
        """ this functions mimics a upgrade but will never remove anything """
        depcache.upgrade(True)
        if depcache.del_count > 0:
            clean(cache,depcache)
        depcache.upgrade()

    def is_security_upgrade(self, pkg, depcache):

        def is_security_upgrade_helper(ver):
            """ check if the given version is a security update (or masks one) """
            security_pockets = [("Ubuntu", "%s-security" % DISTRO),
                                ("gNewSense", "%s-security" % DISTRO),
                                ("Debian", "%s-updates" % DISTRO)]

            for (file, index) in ver.file_list:
                for origin, archive in security_pockets:
                    if (file.archive == archive and file.origin == origin):
                        return True
            return False
        installed_ver = pkg.current_ver
        candidate_ver = depcache.get_candidate_ver(pkg)

        if is_security_upgrade_helper(candidate_ver):
            return True

        # now check for security updates that are masked by a
        # canidate version from another repo (-proposed or -updates)
        for ver in pkg.version_list:
            if (installed_ver and
                apt_pkg.version_compare(ver.ver_str, installed_ver.ver_str) <= 0):
                #print "skipping '%s' " % ver.VerStr
                continue
            if is_security_upgrade_helper(ver):
                return True

        return False

    def apt_get_update_packages(self):
        """
        Return a list of tuple about package status
        """
        pkgs = []
        apt_pkg.init()

        # force apt to build its caches in memory for now to make sure
        # that there is no race when the pkgcache file gets re-generated
        apt_pkg.config.set("Dir::Cache::pkgcache","")
        try:
            cache = apt_pkg.Cache(apt.progress.base.OpProgress())
        except SystemError as e:
            sys.stderr.write("Error: Opening the cache (%s)" % e)
            sys.exit(-1)

        # reading DepCache information and the pin file
        # for any active sessions
        depcache = apt_pkg.DepCache(cache)
        depcache.read_pinfile()
        if os.path.exists(SYNAPTIC_PINFILE):
            depcache.read_pinfile(SYNAPTIC_PINFILE)

        # Init DepCache
        depcache.init()

        try:
            self.saveDistUpgrade(cache,depcache)
        except SystemError as e:
            sys.stderr.write("Error: Marking the upgrade (%s)" % e)
            sys.exit(-1)

        for pkg in cache.packages:
            # Check if the package is already marked as install or upgraded
            if not (depcache.marked_install(pkg) or depcache.marked_upgrade(pkg)):
                continue
            installed_ver = pkg.current_ver
            candidate_ver = depcache.get_candidate_ver(pkg)
            # Compare Candidate Version with the installed Version
            if candidate_ver == installed_ver:
                continue
            record = {"name": pkg.name,
                      "security": self.is_security_upgrade(pkg,depcache),
                      "current_version": installed_ver.ver_str if installed_ver else '-',
                      "candidate_version": candidate_ver.ver_str if candidate_ver else '-',
                      "priority": candidate_ver.priority_str}
            pkgs.append(record)

        if pkgs == None:
            print('pkgs is none')
        print(pkgs)
        return pkgs

def main():
    sys_info = SystemInformation()
    sys_info.client_information()

    update = SystemUpdates(package_manager='apt')
    update.apt_get_update_packages()

if __name__ == '__main__':
    main()
