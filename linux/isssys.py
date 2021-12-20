#!/usr/bin/python3

### Main Libraries ###
import argparse
import sys
import datetime

### System Information Libraries ###
import socket
import platform
import importlib.util

### SystemUpdates Libraries ###
import os
import json

### IssAssist Libraries ###
import requests
import keyring
from keyrings.cryptfile.cryptfile import CryptFileKeyring
import string, random
# import json       # Is Used by SystemUpdates Libraries

### Logging
import logging
log = logging.getLogger(__name__)

class SystemInformation(object):
    """client_infoNonermation
    We will collect all information about your system that is nessecary
    for IssAssist to operate and collect valueble data for our Machine Learning
    to operate as good as possible.
    """

    def __init__(self, name=None, test_ip='8.8.8.8'):
        super(SystemInformation, self).__init__()
        self.name = name
        self.connect_ip_address = test_ip

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
        client['ipv4_address'] = self.get_ip_address(connect=self.connect_ip_address)
        return(client)

    def package_manager(self, pkm='auto'):
        def load_apt():
            try:
                import apt
                import apt_pkg
                import subprocess
                return(True)
            except:
                return (False)

        def load_dnf():
            try:
                import dnf
                import dnf.cli.progress
                return(True)
            except:
                return (False)


        def problem_loading_module(name='Package Manager'):
            msg = 'No module named {}'.format(name)
            log.error(msg)
            raise ModuleNotFoundError(msg)

        if pkm == 'auto':
            # Test if we can load APT Modules
            pkm_test = load_apt()
            if pkm_test:
                return('apt')
            else:
                # APT Module couldn't be loaded
                # Test if we can load DNF Modules
                pkm_test = load_dnf()

            if pkm_test:
                return('dnf')
            else:
                # None of the modules above could be loaded.
                # Rasing an error we couldn't load anything
                problem_loading_module()

        elif pkm == 'dnf':
            ## Force to load DNF Package Manager
            load_dnf()
            if not pkm_test:
                # None of the modules above could be loaded.
                # Rasing an error we couldn't load anything
                problem_loading_module(name='DNF Package Manager')
        elif pkm == 'apt':
            ## Force to load APT Package Manager
            load_apt()
            if not pkm_test:
                # None of the modules above could be loaded.
                # Rasing an error we couldn't load anything
                problem_loading_module(name='DNF Package Manager')
        else:
            # None of the modules above could be loaded.
            # Rasing an error we couldn't load anything
            problem_loading_module()

class IssAssist(object):
    """
    We will communicate and update or creating our instance at IssAssist Agent.
    """

    def __init__(self, credentials=None, *args, **kwargs):
        super(IssAssist, self).__init__()
        self.config = Config()
        self.settings = self.config.get_config(**kwargs)
        self.credentials = credentials

    def keyring_encode(self, *args, **kwargs):
        import base64
        text_string = kwargs['hostname']
        base_text_string = text_string.encode('ascii')
        encrypted_byte = base64.b64encode(base_text_string)
        return (encrypted_byte.decode('ascii'))

    def id_generator(self, size=64, chars=string.ascii_uppercase + string.digits):
        # Auto Generate a string
        return ''.join(random.choice(chars) for _ in range(size))

    def get_credentials(self, *args, **kwargs):
        '''
        Create, Update and Read Password and Token from
        Keyring Manager, will return the password or token.
        '''

        # Change Default Keyring manager.
        CryptFileKeyring.keyring_key = self.keyring_encode(**kwargs)
        keyring.set_keyring(CryptFileKeyring())

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
            # Register a new password.
            log.warning('Register your credentials...')
            keyring.set_password(kwargs['service_name'], kwargs['hostname'], password)

        if 'update' in kwargs:
            # Update a existing password
            log.warning('Update your credentials...')
            keyring.set_password(kwargs['service_name'], kwargs['hostname'], password)

        return(keyring.get_password(kwargs['service_name'], kwargs['hostname']))

    def delete_credentials(self, *args, **kwargs):
        # We are deleting all your credentials
        return(keyring.delete_password(*args, **kwargs))

    def verify_token(self, config, *args, **kwargs):
        # Check if your token is working and if it can access IssAssist.
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
        # Check if tokened is working
        access_token = self.get_credentials(service_name='access_token', **kwargs)
        refresh_token = self.get_credentials(service_name='refresh_token', **kwargs)
        if access_token:
            if self.verify_token(self.settings, token=access_token) == 200:
                new_token = self.refresh_token(self.settings, refresh=refresh_token, **kwargs)
                return (True)
            else:
                if self.verify_token(self.settings, token=refresh_token) == 200:
                    new_token = self.refresh_token(self.settings, refresh=refresh_token, **kwargs)
                    return (True)
                else:
                    log.error('Token is invalid')
                    return (False)

        elif refresh_token:
            if self.verify_token(self.settings, token=refresh_token) == 200:
                new_token = self.refresh_token(self.settings, refresh=refresh_token, **kwargs)
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

        # Register a new device on IssAssist
        response = self.obtain_token(self.config.get_config(),register=True, username=kwargs['hostname'], password1=credentials, password2=credentials, email=email)
        if response.status_code == 201:
            data = json.loads(response.text)
            return(True)
        else:
            log.error('Can not register your device. Get error code ' + str(response.status_code))
            raise Exception('Can not register your device. Get error code ' + str(response.status_code))

    def device_status(self, *args, **kwargs):
        # Check if the device is registered

        url = '{}/{}/'.format(self.settings['url'], 'api/v1/core')
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
        # Will send data to IssAssist Instance
        url = '{}/{}/'.format(self.settings['url'], kwargs['url_extra'])
        credentials = self.get_credentials(service_name='access_token', **kwargs)
        headers = {'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + '{}'.format(credentials)}
        response = requests.post(url, headers=headers, json=kwargs)
        if response.status_code == 201:
            return response
        else:
            log.error('Cannot create data at IssAssist.')
            raise Exception('Cannot create data at IssAssist.')

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

    def __init__(self, package_manager=None, dryrun=False):
        super(SystemUpdates, self).__init__()
        self.package_manager = package_manager
        self.dryrun = dryrun

    def saveDistUpgrade(self,cache,depcache):
        """
        this functions mimics a upgrade but will never remove anything
        """
        depcache.upgrade(True)
        if depcache.del_count > 0:
            clean(cache,depcache)
        depcache.upgrade()

    def apt_is_security_upgrade(self, pkg, depcache, distro):

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

    def dnf_is_security_upgrade(self, pkg):
        pass

    def get_update_packages(self, *args, **kwargs):
        if self.package_manager == 'apt':
            result = self.apt_get_update_packages(**kwargs)
        else:
            result = self.dnf_get_update_packages(**kwargs)
        return (result)

    def apt_get_update_packages(self, *args, **kwargs):
        """
        Return a list of tuple about package status
        """
        log.info('Loading nessecary modules to continue...')
        import apt
        import apt_pkg
        import subprocess

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
                      "security": self.apt_is_security_upgrade(pkg,depcache,DISTRO),
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

    def dnf_get_update_packages(self, *args, **kwargs):
        """
        Return a list of tuple about package status
        Still don't support Security Updates and prioritis patches.
        """
        # Loading DNF Modules and adding progress Meter
        import dnf
        import dnf.cli.progress

        progress = dnf.cli.progress.MultiFileProgressMeter()

        pkgs = []
        # Connect to the DNF and load and update Repo metadata.
        base = dnf.Base()
        base.read_all_repos()
        base.update_cache()

        # Index Installed and packages that can be upgraded.
        base.fill_sack()
        query = base.sack.query()

        # Query all available, installed and upgradble packages.
        query_available = query.available()
        query_installed = query.installed()
        query_upgrades = query.upgrades()
        for pkg_new in query_upgrades:
            query_compare = query_installed.filter(name=pkg_new.name)
            for pkg_old in query_compare:
                record = {"name": pkg_new.name,
                          #"security": self.is_security_upgrade(pkg,depcache, DISTRO),
                          "security": False,
                          "current_version": pkg_old.version,
                          "candidate_version": pkg_new.version,
                          #"priority": candidate_ver.priority_str}
                          "priority": 5}
                pkgs.append(record)

        # Closing session for dnf.base
        base.close()

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
            if self.dryrun:
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
            else:
                priority5 += 1

        list = {'total_updates': total_count,
                'security_updates': security_count,
                'priority1_updates': priority1,
                'priority2_updates': priority2,
                'priority3_updates': priority3,
                'priority4_updates': priority4,
                'priority5_updates': priority5}
        if self.dryrun:
            print('*' * 150)
            print(list)
            print('*' * 150)
        return (list)

class Config(object):
    """
    Configuration Class to update Global Configuration file
    """

    def __init__(self, file='config.json', *args, **kwargs):
        super(Config, self).__init__()
        self.filename = file

    def get_config(self, *args, **kwargs):
        with open(self.filename, "r") as json_data_file:
            data = json.load(json_data_file)
            if kwargs:
                # Modify default settings
                for key, value in kwargs.items():
                    data[key] = value

            return(data)

    def update_config(self, *args, **kwargs):
        # Get old configuration
        # And modify the default configuration with the new configuration
        data = self.get_config(**kwargs)

        # Save the the config file
        with open(self.filename, "w") as json_data_file:
            json.dump(data, json_data_file)

        return(True)

def daemon_service():
    import schedule
    import time
    now = datetime.datetime.now()
    print('Starting service...')
    log.info(str(now) + '  Running Daemon Mode...')
    sleep_seconds = 900  ## Sleeping default time is 900 seconds / 15 min.
    max_count = 4 ## Will sleep 4 times before it do another update check, 4 * 900 seconds is 3600 Seconds / 1 hours.
    count = 5

    ### Modify this section if you want to modify the
    schedule.every(sleep_seconds*max_count).minutes.do(run_daemon_isssys)
    #schedule.every(24).hour.do(isscontrol_client_upgrade)
    #schedule.every().day.at("10:30").do(job)
    #schedule.every(5).to(10).minutes.do(job)
    #schedule.every().monday.do(job)
    #schedule.every().wednesday.at("13:15").do(job)
    #schedule.every().minute.at(":17").do(job)

    while True:
        if count > max_count:
            count = 0
        schedule.run_pending()
        time.sleep(sleep_seconds)
        count =+ 1
    return()

def run_daemon_isssys(*args, **kwargs):
    now = datetime.datetime.now()
    log.info(str(now) + ' Collect System Information')
    print(str(now) + ' Collect System Information')
    sys_info = SystemInformation()
    system_information = sys_info.client_information()
    log.info(str(now) + ' Collect Default Configuration')
    print(str(now) + ' Collect Default Configuration')
    config = Config()

    log.info(str(now) + ' Verify Package Manager')
    print(str(now) + ' Verify Package Manager')
    package_manager = sys_info.package_manager()

    log.info(str(now) + ' Connect to IssAssist')
    print(str(now) + ' Connect to IssAssist')
    issassist = IssAssist()
    if issassist.check_config(hostname=system_information['hostname']):
        print(str(now) + ' Successfully communicate with IssAssist')
        log.info(str(now) + ' Successfully communicate with IssAssist')
    else:
        log.warning(str(now) + ' Cannot connect to IssAssist.')

    log.info(str(now) + ' Collect System Update from your Package Manager')
    print(str(now) + ' Collect System Update from your Package Manager')
    update = SystemUpdates(package_manager=package_manager)
    updates = update.get_update_packages()

    log.info(str(now) + ' Send information to IssAssist')
    print(str(now) + ' Send information to IssAssist')
    isssys_config = config.get_config()
    issassist.send_data(url_extra='api/v1/isssys',
                    **system_information,
                    **updates,
                    **isssys_config,
                    isssys_version=isssys_config['version'])

def main():

    if a.dry_run:
        log.info('Running in Dry-Mode... will not communicate outside this host')

    # Collect all your system information
    sys_info = SystemInformation()
    system_information = sys_info.client_information()
    config = Config()

    if a.daemon:
        # This is only used for running IssSys as a background services.
        # When you kill the service it will automatically stop here and do nothing else.

        daemon_service()
        sys.exit()

    # Cleaning up all configuration.
    if a.cleanup:
        issassist = IssAssist()
        issassist.delete_credentials('access_token', system_information['hostname'])
        issassist.delete_credentials('refresh_token', system_information['hostname'])
        sys.exit()

    # Identify your Package Manager
    if a.manager == 'auto':
        package_manager = sys_info.package_manager(pkm=a.manager)
    else:
        package_manager = a.manager

    if not a.dry_run:
        # Connect to IssAssist to verify connection and registration status
        log.info('Connecting to IssAssist...')
        if a.issassist_url:
            issassist = IssAssist(url=a.issassist_url)
        else:
            issassist = IssAssist()
        if issassist.check_config(hostname=system_information['hostname']):
            log.info('Successfully communicate with IssAssist')
            print('Success talking to IssAssist')
        else:
            log.warning('Cannot connect to IssAssist.')
            log.info('Try to register your device.')
            print('Problem talking to IssAssist')
            if not a.password:
                issassist.register(service_name='username_password',
                                hostname=system_information['hostname'],
                                register=True)
            else:
                issassist.register(service_name='username_password',
                                hostname=system_information['hostname'],
                                password=a.password,
                                register=True)

        # Check if the Device is registered
        device_status = issassist.device_status(hostname=system_information['hostname'])
        if not device_status:
            # Device is not registered
            log.warning('Register your device to IssAssist')
            response = issassist.send_data(url_extra='api/v1/core',
                                        **system_information)
            data = json.loads(response.text)
            config.update_config(host_id=data['id'])

    # Collect your Update Status
    update = SystemUpdates(package_manager=package_manager, dryrun=a.dry_run)
    updates = update.get_update_packages()
    if not a.dry_run:
        # Send Update Information to IssAssist
        isssys_config = config.get_config()
        issassist.send_data(url_extra='api/v1/isssys',
                        **system_information,
                        **updates,
                        **isssys_config,
                        isssys_version=isssys_config['version'])

    if a.print_token:
        if a.dry_run:
            issassist = issassist()

        issassist.print_token(hostname=system_information['hostname'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='''IssSys Agent for IssAssist to collect System Updates information''',
        epilog='''Contact support@isstech.io''',
        prog='./isssys.py'
    )
    mutual = parser.add_mutually_exclusive_group(required=False)

    parser.add_argument("-m", "--manager", default="auto", help="Force IssSys a specific Package Manager like 'apt' or 'yum'.")
    parser.add_argument("-p", "--password", default=None, help="You want to set your own password, default will be auto 128 characters generated")
    parser.add_argument("-e", "--email", default=None, help="System Owners email address")
    parser.add_argument("-T", "--print-token", action = "store_true", help="Print your token on your screen")
    parser.add_argument("-u", "--issassist-url", default=None, help = "URL to IssAssist, default is to use the configuration file")
    mutual.add_argument("--dry-run", action = "store_true", help="Dry-run this operation to just view the result that will be past to IssAssist")
    mutual.add_argument("--cleanup", action = "store_true", help="Clean up all credentials for IssSys")
    mutual.add_argument("--daemon", action="store_true", help = "Run the script as a daemon")

    a = parser.parse_args()
    main()
