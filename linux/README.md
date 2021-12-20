# IssSys for Linux
This client service will check for Linux updates every hours and reporting it back to IssAssist

Before you install please check the prerequirement section before start.

## Prerequirement
### Support Operating Systems
| Operating System | Supported |
| :---             |   :---:   |
| Ubuntu 21.04     |     X     |
| Fedora 35        |     X     |

### Dependencies
You most have installed `python3-apt` or `python3-dnf` to get this working.

## Installation
Download the last code from Github in to directory `/opt/isstech`
```
git clone https://github.com/IssTech/IssSys.git
```
Install all depenancies that need to be run.
```
sudo pip install -r requirement.txt
```

Change the configuration file, by edit the `config.json` and modify the URL line

Copy the service file `isssys.service` in to `/etc/systemd/system` directory, enable and start the service.
```
sudo cp isssys.service /etc/systemd/system
sudo systemctl enable isssys.service
sudo systemctl start isssys.service
```


## Know Issues
There is a few known issues that will be fixed in coming release.

* If IssSyS Services can't reach IssAssist Server it will kill the service and you need to manually restart the service.

* If you are using Fedora 35 you can't start the service, workaround for this is to run IssSys using crontab.
