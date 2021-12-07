### Main Libraries ###
import argparse

### System Information Libraries ###
import socket
import platform

### SystemUpdates Libraries ###
import os
import json

### IssBot Libraries ###
import requests
import keyring
import string, random
# import json       # Is Used by SystemUpdates Libraries

### Logging
import logging
log = logging.getLogger(__name__)

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
        client['ipv4_address'] = self.get_ip_address(connect="8.8.8.8")
        return(client)

    def package_manager(self):
        try:
            import apt, apt_pkg
            import subprocess
            ISSSYS_PINFILE = "/var/lib/isstech"
            DISTRO = subprocess.check_output(["lsb_release", "-c", "-s"],
                                             universal_newlines=True).strip()
            log.info('Running Debian simular distribution, using apt')
            return('apt')
        except:
            pass

class IssBot(object):
    """
    We will communicate and update or creating our instance at IssBot Agent.
    """

    def __init__(self, issbot=None, credentials=None):
        super(IssBot, self).__init__()
        self.issbot = issbot
        self.credentials = credentials

    def config(self):
        # This function help us to collect configuration.
        # It will read data from our config file.

        if self.issbot:
            if self.issbot == 'file':
                with open('config.json') as json_data_file:
                    data = json.load(json_data_file)
            else:
                with open('config.json') as json_data_file:
                    data = json.load(json_data_file)
                data['url'] = self.issbot
        else:
            with open('config.json') as json_data_file:
                data = json.load(json_data_file)
        return(data)

    def id_generator(self, size=64, chars=string.ascii_uppercase + string.digits):
        # Auto Generate a string
        return ''.join(random.choice(chars) for _ in range(size))

    def get_credentials(self, *args, **kwargs):
        # We will create/update and return our secret)
        if 'password' in kwargs:
            password = kwargs['password']
        elif 'access_token' in kwargs:
            password = kwargs['access_token']
        elif 'refresh_token' in kwargs:
            password = kwargs['refresh_token']
        else:
            password = self.id_generator(size=128)

        if 'register' in kwargs:
            log.warning('Register your credentials...')
            keyring.set_password(kwargs['service_name'], kwargs['hostname'], password)

        if 'update' in kwargs:
            log.warning('Update your credentials...')
            keyring.set_password(kwargs['service_name'], kwargs['hostname'], password)
        return(keyring.get_password(kwargs['service_name'], kwargs['hostname']))

    def update_config(self, *args, **kwargs):
        # Update your configuration file
        with open('config.json', "r") as json_data_file:
            data = json.load(json_data_file)

        for key, value in kwargs.items():
            data[key] = value

        with open('config.json', "w") as json_data_file:
            json.dump(data, json_data_file)

        return(True)

    def verify_token(self, config, *args, **kwargs):
        # Check if your token is working and if it can access IssBot.
        log.info('Verifing your token...')
        url = config['url'] + '/api/auth/token/verify/'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=kwargs)
        if response.status_code == 200:
            log.info('Token successfully verified')
        else:
            log.warning("Verify token failed with errorcode " + str(response.status_code))
        return(response.status_code)

    def refresh_token(self, config, *args, **kwargs):
        # Refresh your Token
        log.info('Refresh your token')
        url = config['url'] + '/api/auth/token/refresh/'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=kwargs)
        token_data = json.loads(response.text)
        self.get_credentials(update=True, service_name='access_token', access_token=token_data['access'], **kwargs )
        return(response)

    def obtain_token(self, config, register=False, refresh=False, *args, **kwargs):
        # Create and Retain your token
        print('Obtain New Token')
        if register:
            url = '{}/{}/{}/'.format(config['url'], 'api/auth', 'registration')
        else:
            url = '{}/{}/'.format(config['url'], 'api/auth/token')

        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, json=kwargs)
        if response.status_code == 201:
            token_data = json.loads(response.text)
            self.get_credentials(update=True, service_name='access_token', access_token=token_data['access_token'], hostname=kwargs['username'], **kwargs )
            self.get_credentials(update=True, service_name='refresh_token', refresh_token=token_data['refresh_token'], hostname=kwargs['username'], **kwargs )

        return(response)

    def check_config(self, *args, **kwargs):
        config = self.config()
        access_token = self.get_credentials(service_name='access_token', **kwargs)
        refresh_token = self.get_credentials(service_name='refresh_token', **kwargs)
        if access_token:
            if self.verify_token(config, token=access_token) == 200:
                new_token = self.refresh_token(config, refresh=refresh_token, **kwargs)
                return (True)
            else:
                if self.verify_token(config, token=refresh_token) == 200:
                    new_token = self.refresh_token(config, refresh=refresh_token, **kwargs)
                    return (True)
                else:
                    log.error('Token is invalid')
                    return (False)

        elif refresh_token:
            if self.verify_token(config, token=refresh_token) == 200:
                new_token = self.refresh_token(config, refresh=refresh_token, **kwargs)
                return (True)
            else:
                log.error('Token is invalid')
                return (False)
        else:
            print('Token does not exist')
            return(False)

    def register(self, *args, **kwargs):
        credentials = self.get_credentials(**kwargs)
        if 'email' in kwargs:
            email = kwargs['email']
        else:
            email = kwargs['hostname'] + '@fakecompany.com'

        # Register a new device on IssBot
        response = self.obtain_token(self.config(),register=True, username=kwargs['hostname'], password1=credentials, password2=credentials, email=email)
        if response.status_code == 201:
            data = json.loads(response.text)
            return(True)
        else:
            log.error('Can not register your device. Get error code ' + str(response.status_code))
            raise Exception('Can not register your device. Get error code ' + str(response.status_code))

    def device_status(self, *args, **kwargs):
        config = self.config()
        url = '{}/{}/'.format(config['url'], 'api/v1/core')
        credentials = self.get_credentials(service_name='access_token', **kwargs)
        headers = {'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + '{}'.format(credentials)}
        response = requests.get(url, headers=headers)
        if len(response.text) > 2:
            return response
        else:
            log.error('Device is not registered')
            return False

    def send_data(self, *args, **kwargs):
        config = self.config()
        url = '{}/{}/'.format(config['url'], kwargs['url_extra'])
        credentials = self.get_credentials(service_name='access_token', **kwargs)
        headers = {'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + '{}'.format(credentials)}
        response = requests.post(url, headers=headers, json=kwargs)
        if response.status_code == 201:
            return response
        else:
            log.error('Cannot create data at IssBot.')
            raise Exception('Cannot create data at IssBot.')

    def print_token(self, *args, **kwargs):
        print('*' * 100)
        print('Your Access Token: ' + self.get_credentials(service_name='access_token', **kwargs))
        print('Your Refresh Token: ' + self.get_credentials(service_name='refresh_token', **kwargs))
        print('*' * 100)
        return(True)

class SystemUpdates(object):
    """
    In this class can you identify all system updates and process each update
    """

    def __init__(self, package_manager=None):
        super(SystemUpdates, self).__init__()
        self.package_manager = package_manager

    def saveDistUpgrade(self,cache,depcache):
        """
        this functions mimics a upgrade but will never remove anything
        """
        depcache.upgrade(True)
        if depcache.del_count > 0:
            clean(cache,depcache)
        depcache.upgrade()

    def is_security_upgrade(self, pkg, depcache, distro):

        def is_security_upgrade_helper(ver):
            """
            check if the given version is a security update (or masks one)
            """
            security_pockets = [("Ubuntu", "%s-security" % distro),
                                ("gNewSense", "%s-security" % distro),
                                ("Debian", "%s-updates" % distro)]

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
            if self.package_manager == 'apt':
                import apt_pkg
                if (installed_ver and
                    apt_pkg.version_compare(ver.ver_str, installed_ver.ver_str) <= 0):
                    #print "skipping '%s' " % ver.VerStr
                    continue
            if is_security_upgrade_helper(ver):
                return True

        return False

    def get_update_packages(self, *args, **kwargs):
        if self.package_manager == 'apt':
            result = self.apt_get_update_packages(**kwargs)
        else:
            result = self.yum_get_update_packages(**kwargs)
        return (result)

    def apt_get_update_packages(self, *args, **kwargs):
        """
        Return a list of tuple about package status
        """
        log.info('Loading nessecary modules to continue...')
        import apt, apt_pkg, subprocess
        ISSSYS_PINFILE = "/var/lib/isstech"
        DISTRO = subprocess.check_output(["lsb_release", "-c", "-s"],
                                         universal_newlines=True).strip()

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
        if os.path.exists(ISSSYS_PINFILE):
            depcache.read_pinfile(ISSSYS_PINFILE)

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
                      "security": self.is_security_upgrade(pkg,depcache,DISTRO),
                      "current_version": installed_ver.ver_str if installed_ver else '-',
                      "candidate_version": candidate_ver.ver_str if candidate_ver else '-',
                      #"priority": candidate_ver.priority_str}
                      "priority": candidate_ver.priority}
            pkgs.append(record)

        if pkgs == None:
            print('pkgs is none')
            return(pkgs)
        else:
            package_count = self.package_count(pkgs, **kwargs)
            return package_count

    def yum_get_update_packages(self, *args, **kwargs):
        """
        THIS IS NOT READY YET
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
        if os.path.exists(ISSSYS_PINFILE):
            depcache.read_pinfile(ISSSYS_PINFILE)

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
                      "security": self.is_security_upgrade(pkg,depcache, DISTRO),
                      "current_version": installed_ver.ver_str if installed_ver else '-',
                      "candidate_version": candidate_ver.ver_str if candidate_ver else '-',
                      #"priority": candidate_ver.priority_str}
                      "priority": candidate_ver.priority}
            pkgs.append(record)

        if pkgs == None:
            print('pkgs is none')
        else:
            package_count = self.package_count(pkgs)
        return pkgs

    def package_count(self, output, *args, **kwargs):
        list = {}
        total_count = 0
        security_count = 0
        priority1 = 0
        priority2 = 0
        priority3 = 0
        priority4 = 0
        priority5 = 0

        for item in output:
            if 'dryrun' in kwargs:
                print(item)

            total_count += 1
            if item['security'] == True:
                security_count += 1
            if item['priority'] == 1:
                priority1 += 1
            elif item['priority'] == 2:
                priority2 += 1
            elif item['priority'] == 3:
                priority3 += 1
            elif item['priority'] == 4:
                priority4 += 1
            elif item['priority'] == 5:
                priority5 += 1

        list = {'total_updates': total_count,
                'security_updates': security_count,
                'priority1_updates': priority1,
                'priority2_updates': priority2,
                'priority3_updates': priority3,
                'priority4_updates': priority4,
                'priority5_updates': priority5}
        if 'dryrun' in kwargs:
            print('*' * 150)
            print(list)
            print('*' * 150)
        return (list)

def main():
    if a.dry_run:
        log.info('Running in Dry-Mode... will not commucate outside this host')

    # Collect all your system information
    sys_info = SystemInformation()
    system_information = sys_info.client_information()

    # Identify your Package Manager
    if a.manager == 'auto':
        package_manager = sys_info.package_manager()
    else:
        package_manager = a.manager

    if not a.dry_run:
        # Connect to IssBot to verify connection and registration status
        log.info('Connecting to IssBot...')
        if a.issbot_url:
            issbot = IssBot(issbot=a.issbot_url)
        else:
            issbot = IssBot()
        if issbot.check_config(hostname=system_information['hostname']):
            log.info('Successfully communicate with IssBot')
            print('Success talking to IssBot')
        else:
            log.warning('Cannot connect to IssBot.')
            log.info('Try to register your device.')
            print('Problem talking to IssBot')
            if not a.password:
                issbot.register(service_name='username_password',
                                hostname=system_information['hostname'],
                                register=True)
            else:
                issbot.register(service_name='username_password',
                                hostname=system_information['hostname'],
                                password=a.password,
                                register=True)

        # Check if the Device is registered
        device_status = issbot.device_status(hostname=system_information['hostname'])
        if not device_status:
            # Device is not registered
            log.info('Send Update Status to IssBot')
            response = issbot.send_data(url_extra='api/v1/core',
                                        **system_information)
            data = json.loads(response.text)
            issbot.update_config(host_id=data['id'])

    # Collect your Update Status
    update = SystemUpdates(package_manager=package_manager)
    if not a.dry_run:
        # Send Update Information to IssBot
        updates = update.get_update_packages()
        isssys_config = issbot.config()
        issbot.send_data(url_extra='api/v1/isssys',
                        **system_information,
                        **updates,
                        **isssys_config,
                        isssys_version=isssys_config['version'])
    else:
        updates = update.get_update_packages(dryrun=True)

    if a.print_token:
        if a.dry_run:
            issbot = IssBot()

        issbot.print_token(hostname=system_information['hostname'])

if __name__ == '__main__':
    p = argparse.ArgumentParser(
        description='''IssSys Agent for IssBot to collect System Updates information''',
        epilog='''Contact support@isstech.io''',
        prog='python3 isssys.py'
    )
    p.add_argument("-u", "--issbot-url", default='file', help = "URL to IssBot, default is to use the configuration file")
    p.add_argument("-m", "--manager", default="auto", help="Force IssSys a specific Package Manager like 'apt' or 'yum'.")
    p.add_argument("-p", "--password", default=None, help="You want to set your own password, default will be auto 128 characters generated")
    p.add_argument("-e", "--email", default=None, help="System Owners email address")
    p.add_argument("-T", "--print-token", action = "store_true", help="Print your token on your screen")
    p.add_argument("--dry-run", action = "store_true", help="Dry-run this operation to just view the result that will be past to IssBot")
    a = p.parse_args()
    main()
