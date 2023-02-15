# -*- coding: utf-8 -*-
"""IVI POC container proxy config tool.

This tool is used to auto configure docker proxy.

Precondition: 
    log into container of android: docker exec -it steam bash;
    configure apt proxy and source.lists if needed in your network;
    sudo apt-get update && sudo apt-get install -y adb
    git clone https://github.com/szhen11/tools.git
    cd tools/ivi/

Execution:
    python3 proxy_config.py [-i android_ip] [-l DEBUG|INFO]

Author: shuang.zheng@intel.com

Modified:

"""
import os, time, argparse, subprocess
import re, traceback, logging, datetime, ipaddress, json

class ConfigureInputDevice():
    def __init__(self, outputdir='.'):
        self._adb = 'adb '
        self._outputdir = outputdir

    def setup_adb_connection(self, ip):
        print('='*20+'{:=<{width}}'.format(' Step 5.3. connect Android with IP', width=80))
        self.verify_adb()
        if ip is None:
            for i in range(5):
                ip = input('Please input the IP address of the Android: ')
                try:
                    ipaddress.ip_address(ip)
                except Exception as e:
                    logging.warning(str(e))
                    ip = None
                else:
                    break
            if i == 5:
                ip = None
        if ip is not None:
            logging.info('Trying to connect to android with IP: {}'.format(ip))
            (output, err) = self.run_host_cmd('adb connect {}:5555'.format(ip))
            if 'connected to {}:5555'.format(ip) not in output:
                msg = 'Failed to connect to Android with IP: {} {}'.format(output, err)
                logging.error('Please make sure you input the correct Android IP, and enabled Adb Debugging in Android(quickly tap Settings->About->Build Number to Developer Options, and enable Adb debugging in it).')
                logging.error(msg)
                raise Exception(msg)
            self._adb = '{}-s {} '.format(self._adb, ip)
        else:
            msg ='Failed to get IP of Android.'
            logging.error(msg)
            raise Exception(msg)
            
        (output, err) = self.run_host_cmd(self._adb + 'root')
        if ('restarting adbd as root' not in output) and ('already running' not in output):
            msg = 'Adb root not succeeded: {} {}'.format(output, err) 
            logging.error(msg)
            raise Exception(msg)

        (output, err) = self.run_host_cmd(self._adb + 'remount')
        if 'remount succeeded' not in output:
            msg = 'Remount not succeeded: {} {}'.format(output, err)
            logging.error(msg)
            raise Exception(msg)
        
        logging.info('Connect to android device successfully')
        # print('='*20+'{:=<{width}}'.format(' Step 0. connected to Android device successfully. ', width=80))

    def config_docker_proxy(self):
        print('='*20+'{:=<{width}}'.format(' Step 6.6. configure docker proxy if needed ', width=80))
        logging .info('Please input the proxy url for container if you need it for installing ubuntu packages or downloading resources in the following configuration steps.\n         or press n and Enter to ignore this step.')
        choice = input('INFO     [proxy url/n] ')
        if choice in ['n', 'N', '']:
            logging.info('You selected n, ignore this step.')
            return False
        else:
            logging.info('You typed proxy url: {}'.format(choice))
            (output, err) = self.run_host_cmd(self._adb+'shell docker ps --no-trunc | grep steam')
            if 'steam' not in output:
                logging.error('No steam container founded')
                raise Exception('No steam container founded')
            else:
                container_id = output.strip().split()[0]
                container_config = '/data/docker/lib/docker/containers/{}/config.v2.json'.format(container_id)
                logging.debug('container config file: {}'.format(container_config))
                container_config_host = os.path.join(self._outputdir, 'config.v2.json')
                container_config_host2 = os.path.join(self._outputdir, 'config2.v2.json')
                self.run_host_cmd(self._adb+'pull {} {}'.format(container_config, self._outputdir))
                self.run_host_cmd('mv {} {}'.format(container_config_host, container_config_host2))
                with open(container_config_host2, 'r') as f1:
                    content = f1.read().strip()
                    jcontent = None
                    try:
                        jcontent = json.loads(content)
                        if 'Config' in jcontent and 'Env' in jcontent['Config']:
                            http_item = None
                            https_item = None
                            for item in jcontent['Config']['Env']:
                                if item.startswith('http_proxy'):
                                    http_item = item
                                elif item.startswith('https_proxy'):
                                    https_item = item
                            if http_item:
                                jcontent['Config']['Env'].remove(http_item)
                            if https_item:
                                jcontent['Config']['Env'].remove(https_item)
                            jcontent['Config']['Env'].append('http_proxy={}'.format(choice))
                            jcontent['Config']['Env'].append('https_proxy={}'.format(choice))
                        else:
                            logging.warning("Can't find 'Config -> Env' in config.v2.json, ignore proxy configuration.")
                            if 'Config' not in jcontent:
                                jcontent['Config']={}
                            jcontent['Config']['Env'] = []
                            jcontent['Config']['Env'].append('http_proxy={}'.format(choice))
                            jcontent['Config']['Env'].append('https_proxy={}'.format(choice))
                    except Exception as e:
                        logging.error('configure docker proxy failed: '+str(e))
                        raise Exception(str(e))
                    else:
                        with open(container_config_host, 'w') as f2: 
                            content2 = json.dumps(jcontent)
                            f2.write(content2)
                        self.run_host_cmd(self._adb+'push {} /data/docker/lib/docker/containers/{}/'.format(container_config_host, container_id))
                        (output, err) = self.run_host_cmd(self._adb+'shell cat {}'.format(container_config))
                        logging.debug(output)
                        if choice not in output:
                            raise Exception('Proxy {} not configured in container config file: {}'.format(choice, output))
                        else:
                            logging.info('Configure container proxy: {} done.'.format(choice))
                            logging.info('You have configure the proxy of docker container, the config tool will direct you to reboot system. After the Android rebooted, you can rerun this tool to continue the configurations with proxy effectively.')
        # print('='*20+'{:=<{width}}'.format(' Step 3. finished. ', width=80))
        logging.info('Step 6.6 finished.')
        return True
    
    def reboot_android(self):
        print('='*20+'{:=<{width}}'.format('  Step Reboot. reboot Android to make the configuration effetctive', width=80))
        choice = input('INFO     Do you want to adb reboot Android to make the configuration effective? [y/n] ')
        if choice in ['y']:
            self.run_host_cmd(self._adb + 'reboot')
        else:
            logging.info('Ignore this step, please reboot Android by yourself.')
        # print('{:=<{width}}'.format(' Step 4. adb reoboot finished. ', width=80))
        logging.info('Step Reboot finished.')
        # print('='*20+'{:=<{width}}'.format('  Step 4. finished.', width=80))
    
    def verify_adb(self):
        (output, err) = self.run_host_cmd('adb devices')
        if 'List of devices attached' not in output:
            msg = 'adb not installed properly, please install adb before configuration.'
            logging.error(msg)
            raise Exception(msg)

    def run_host_cmd(self, cmd, timeout=30):
        output = ''
        errmsg = ''
        try:
            logging.debug('Run host command: {}'.format(cmd))
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, timeout=timeout).decode("utf-8")
        except subprocess.CalledProcessError as ex:
            errmsg = ex.output.decode().strip()
            msg = '''Run host command failed:
            cmd: {}
            message: {}'''.format(cmd, errmsg)
            logging.debug(msg)
        except Exception as ex: 
            errmsg = str(ex).strip()
            msg = '''Run host command failed:
            cmd: {}
            message: {}'''.format(cmd, errmsg)
            logging.debug(msg)
            #raise Exception(msg)
        
        return (output, errmsg)


if __name__ == "__main__":
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    outputdir = os.path.join(os.getcwd(), '_log_'+timestamp)
    
    parser = argparse.ArgumentParser(description='IVI POC container proxy config tool')
    parser.add_argument("-i", "--ip", dest="ip", default=None,
                    help="IP Address of Android")
    parser.add_argument("-l", "--loglevel", dest="loglevel", default='INFO',
                    help="IP Address of Android")
    parser.add_argument("-o", "--outputdir", dest="outputdir", default=outputdir,
                    help="the directory to store logs")
    args = parser.parse_args()

    if args.loglevel == 'DEBUG':
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
    os.makedirs(outputdir)
    logging.basicConfig(
        level=loglevel,
        format="%(levelname)-8s %(message)s",
        handlers=[
            logging.FileHandler("{0}/{1}.log".format(outputdir, 'execution')),
            logging.StreamHandler()
        ]
    )

    config = ConfigureInputDevice(args.outputdir)
    config.setup_adb_connection(args.ip)
    configed = config.config_docker_proxy()
    config.reboot_android()
    print('='*20+'{:=<{width}}'.format(' ALL DONE ', width=80))


