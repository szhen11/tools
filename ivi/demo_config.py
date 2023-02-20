# -* coding: utf-8 -*-
"""IVI POC Demo config tool.

This tool is used to auto configure IVI POC Demo touch/keyboard/mouse/
audio/multiple hardware planes/openvino related configs.

Precondition: 
    log into container of android: docker exec -it steam bash;
    configure apt proxy and source.lists if needed in your network;
    sudo apt-get update && sudo apt-get install -y adb
    git clone https://github.com/szhen11/tools.git
    cd tools/ivi/

Execution:
    python3 demo_config.py [-i android_ip] [-l DEBUG|INFO]

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
    
    def configure_touch_for_android(self):
        # print('-'*20+'{:60s}'.format('Step 1. enable multiple touch screen(s) for Android')+'-'*20)
        print('='*20+'{:=<{width}}'.format(' Step 5.4. enable multiple touch screen(s) for Android ', width=80))
        logging.info('Please make sure the touch screen(s) connected to the iGPU before this configuration step!')
        TOUCH_DETECT_RETRY_TIMES = 10
        touch_device_list = []
        input_device_list = self.get_input_device_list()
        display_info_list = self.get_display_info_list()
        (output, err) = self.run_host_cmd(self._adb+'uninstall com.intel.touchme')
        logging.debug(output+err)
        (output, err) = self.run_host_cmd(self._adb+'install -r TouchMe.apk')
        logging.debug(output+err)
        if err:
            logging.error('install TouchMe.apk failed: '+err)
        index = 0
        for display_info in display_info_list:
            # if 'DeviceType' not in display_info or 'TOUCH' not in display_info['DeviceType']:
            #     continue
            index += 1
            for i in range(TOUCH_DETECT_RETRY_TIMES):
                print('-'*20+'{:-<{width}}'.format('Step 5.4.{}. detect the touch screen for Display {}'.format(index, display_info['uniqueId']), width=80))
                logging.info('Starting to detect touch screen for Display: Id={} uniqueId={} port={} physicalFrame={}...'.format(display_info['displayId'], display_info['uniqueId'], display_info['port'], display_info['physicalFrame']))
                logging.info('Launching TouchMe Application on Display {}'.format(display_info['uniqueId']))
                self.run_host_cmd('{} shell am force-stop com.intel.touchme'.format(self._adb))
                self.run_host_cmd('{} shell am start --user 10 --display {} -n "com.intel.touchme/com.intel.touchme.MainActivity" -a android.intent.action.MAIN -c android.intent.category.LAUNCHER'.format(self._adb, display_info['displayId']))
                self.run_host_cmd(self._adb + 'shell rm -rf /data/local/getevent.log')
                self.run_host_cmd(self._adb + 'shell "getevent > /data/local/getevent.log 2>&1 &"')
                logging.info('Please touch the screen which launching TouchMe Application, and then press Enter to continue;')
                print('         Or press n and Enter to ignore this step if the screen which launching TouchMe App is untouchable: '.format(index))
                choice = input('INFO     [y/n] ')
                if choice == 'n':
                    logging.info('You selected n, ignore this step to detect Display {}.'.format(display_info['uniqueId']))
                    self.run_host_cmd(self._adb + '''shell "ps -ef|grep getevent|grep -v grep|awk '{print \$2}'|xargs kill -9"''')
                    break
                else:
                    time.sleep(3)
                    self.run_host_cmd(self._adb + '''shell "ps -ef|grep getevent|grep -v grep|awk '{print \$2}'|xargs kill -9"''')
                    (output, err) = self.run_host_cmd(self._adb+'shell cat /data/local/getevent.log')
                    logging.debug(output)
                    logging.debug(err)
                    event_list = []
                    touch_device = None
                    for line in reversed(output.split('\n')):
                        if line.strip().startswith('/dev/input/event'):
                            event = line.strip().split(':')[0].strip()
                            if event not in event_list:
                                event_list.append(event)
                    for event in event_list:
                        for input_device in input_device_list:
                            if input_device['Path'] == event and 'TOUCH | TOUCH_MT | EXTERNAL' in input_device['Classes']:
                            #if input_device['Path'] == event and 'TOUCH' in input_device['Classes']:
                                touch_device = input_device
                                break
                    if touch_device:
                        '''tdi = None
                        for di in display_info_list:
                            if 'devices' in di and str(touch_device['ID']) in di['devices']:
                                tdi = di
                        if tdi is None:
                            logging.warning("Can't detected current touch screen for event {}".format(str(event_list)))
                        else:
                            logging.info('Detected current touch screen {}.'.format(touch_device['Name']))
                            touch_device_list.append([tdi, touch_device])
                            logging.debug(touch_device)
                            logging.debug(tdi)'''
                        logging.info('Detected current touch screen {}.'.format(touch_device['Name']))
                        touch_device_list.append([display_info, touch_device])
                        break
                    else:
                        logging.warning("Can't detected current screen to be touchable.")
        
        if touch_device_list:
            for input_device in input_device_list:
                if 'Classes' in input_device and 'TOUCH | TOUCH_MT | EXTERNAL' in input_device['Classes']:
                    logging.debug('Remove idc files for {} if existed'.format(input_device['Name']))
                    if input_device['vendor'] and input_device['product']:
                        self.run_host_cmd(self._adb+'shell rm -rf /system/usr/idc/Vendor_{}_Product_{}.idc'.format(input_device['vendor'], input_device['product']))
                    if input_device['Location']:
                        name = input_device['Location'].strip()
                        char_list = '/,:.'
                        for char in char_list:
                            name = name.replace(char, '_')
                        self.run_host_cmd(self._adb+'shell rm -rf /system/usr/idc/{}.idc'.format(name))

        new_vendor_product_list = []
        for touch_device in touch_device_list:
            input_device = touch_device[1]
            if 'vendor' in input_device and 'product' in input_device:
                new_vendor_product_list.append([input_device['vendor'], input_device['product']])


        #if True: 
        #if len(touch_device_list) == 2 \
        #        and touch_device_list[0][1]['vendor'] == touch_device_list[1][1]['vendor'] \
        #        and touch_device_list[0][1]['product'] == touch_device_list[1][1]['product']:
        # Creating idc file for 2 touch devices with same manufacturers 
        for touch_device in touch_device_list:
            display_info = touch_device[0]
            touch_screen = touch_device[1]
            logging.debug(touch_screen)
            logging.debug(display_info)
            logging.info('Starting to create idc file for touch screen: {}. {} {}'.format(display_info['displayId'], display_info['uniqueId'], touch_screen['Name']))
            vp_num = 0
            for vp in new_vendor_product_list:
                if vp[0] == touch_screen['vendor'] and vp[1] == touch_screen['product']:
                    vp_num += 1
            if vp_num > 1:
                logging.debug('There are duplicated vendor+product ids for touch devices.')
                name = touch_screen['Location'].strip()
                char_list = '/,:.'
                for char in char_list:
                    name = name.replace(char, '_')
                idc_file_name = os.path.join(self._outputdir, '{}.idc'.format(name))
                with open(idc_file_name, 'w') as f:
                    f.write('device.internal = 0\n')
                    f.write('touch.deviceType = touchScreen\n')
                    f.write('touch.displayId = {}'.format(display_info['uniqueId']))
                self.run_host_cmd(self._adb + 'push {} /system/usr/idc'.format(idc_file_name))
                (output, err) = self.run_host_cmd(self._adb + 'shell cat /system/usr/idc/{}'.format('{}.idc'.format(name)))
                if display_info['uniqueId'] in output:
                    logging.debug(output)
                    logging.info('Creating idc file {} for Touch Display {} successfully.'.format('{}.idc'.format(name), display_info['uniqueId']))
                else:
                    logging.error('Creating idc file {} for Touch Display {} failed.'.format('{}.idc'.format(name), display_info['uniqueId']))
                    logging.error(output) if output else ''
                    logging.error(err) if err else ''
            else:
                logging.debug('No duplicated vendor+product ids for touch devices.')
                idc_file_name = os.path.join(self._outputdir,  
                    'Vendor_{}_Product_{}.idc'.format(touch_screen['vendor'], touch_screen['product']))
                with open(idc_file_name, 'w') as f:
                    f.write('device.internal = 0\n')
                    f.write('touch.deviceType = touchScreen\n')
                    f.write('touch.displayId = local: {}'.format(display_info['uniqueId']))
                self.run_host_cmd(self._adb + 'push {} /system/usr/idc'.format(idc_file_name))
                (output, err) = self.run_host_cmd(self._adb + 'shell cat /system/usr/idc/{}'.format('Vendor_{}_Product_{}.idc'.format(touch_screen['vendor'], touch_screen['product'])))
                if display_info['uniqueId'] in output:
                    logging.debug(output)
                    logging.info('Creating idc file {} for Touch Display {} successfully.'.format('Vendor_{}_Product_{}.idc'.format(touch_screen['vendor'], touch_screen['product']), display_info['uniqueId']))
                else:
                    logging.error('Creating idc file {} for Touch Display {} failed.'.format('Vendor_{}_Product_{}.idc'.format(touch_screen['vendor'], touch_screen['product']), display_info['uniqueId']))
                    logging.error(output) if output else ''
                    logging.error(err) if err else ''
        # print('='*20+'{:=<{width}}'.format(' Step 1. finished.', width=80))
        logging.info('Step 5.4 finished.')
    
    def enable_multiple_hardware_plan(self):
        print('='*20+'{:=<{width}}'.format(' Step 5.5. enable multiple hardware plane to boost display performance ', width=80))
        # print('='*20+'{:=<{width}}'.format(' Step 3. finished. ', width=80))
        (output, err) = self.run_host_cmd(self._adb+'shell ls /dev/dri | wc -l')
        num = 0
        for line in output.split('\n'):
            if line.strip().isdigit():
                num = int(line.strip())
                break
        if num < 2:
            logging.error('file check in /dev/dri of Android failed: {}'.format(output+err))
            logging.info('Ignore this step.')
            return
        if num > 2:
            logging.info('The Android is AaaG and no need to enable multiple hardware planes')
            return
        logging.info('Starting to enable multiple hardware planes on Android BM')
        logging.info('Starting to set /vendor/build.prop (this may take a few seconds) ...')
        self.run_host_cmd(self._adb+'pull /vendor/build.prop {}'.format(self._outputdir))
        build_prop_old = os.path.join(self._outputdir, 'build_old.prop')
        build_prop = os.path.join(self._outputdir, 'build.prop')
        self.run_host_cmd('mv {} {}'.format(build_prop, build_prop_old))
        enable_flag = False
        num_flag = False
        with open(build_prop_old, 'r') as f1:
            with open(build_prop, 'w') as f2:
                for line in f1.readlines():
                    if line.startswith('vendor.hwcomposer.planes.enabling='):
                        enable_flag = True
                        f2.write('vendor.hwcomposer.planes.enabling=1\n')
                    elif line.startswith('vendor.hwcomposer.planes.num='):
                        num_flag = True
                        f2.write('vendor.hwcomposer.planes.num=2\n')
                    else:
                        f2.write(line)
            if not enable_flag:
                with open(build_prop, 'a') as f2:
                    f2.write('\nvendor.hwcomposer.planes.enabling=1')
            if not num_flag:
                with open(build_prop, 'a') as f2:
                    f2.write('\nvendor.hwcomposer.planes.num=2')
        self.run_host_cmd(self._adb+'push {} /vendor/'.format(build_prop))
        (output, err) = self.run_host_cmd(self._adb+'shell cat /vendor/build.prop|grep vendor.hwcomposer.planes.')
        logging.debug(output)
        if '.enabling=1' not in output and '.num=2' not in output:
            logging.error('Configure multiple hardware plan in build.prop failed: {}'.format(output))
        else:
            logging.info('Configure multiple hardware plan in build.prop successfully.')
        logging.info('Step 5.5 finished.')
    
    def configure_audio(self):
        print('='*20+'{:=<{width}}'.format(' Step 6.3. Linux Container Audio Configuration ', width=80))
        logging.info('Starting to install speaker-test to test the audio in container')
        (output, err) = self.run_host_cmd('sudo apt install -y alsa-utils && echo "package install successfully."')
        logging.debug(output+err)
        if 'package install successfully.' not in output:
            logging.error('Install alsa-utils for speaker-test failed: {}'.format(output))
            raise Exception(output)
        logging.info('Starting speaker-test, make sure at least one audio output device is connected to Android host,')
        logging.info('for example, a headset and listen to the audio, You should hear some noice from it.')
        self.run_host_cmd("speaker-test > /dev/null 2>&1 &")
        #os.system('speaker-test 2>&1 &')
        logging.info('If you hear some noise from the audio device, press n and Enter to ignore sound card config;')
        print('         press other keys to configure sound cards:')
        choice = input('INFO     Configure sound card? [y/n] ')
        if choice in ['n']:
            logging.info('You selected n, the audio is working properly and no need to configure sound cards.')
        else:
            logging.info('You did not select yes, start to configure sound card, detected sound cards:')
            (output, err) = self.run_host_cmd('cat /proc/asound/cards')
            audio_device_list = []
            start_flag = False
            audio_device = {}
            for line in output.split('\n'):
                if line.strip() and line.strip().split()[0].isdigit() and not start_flag:
                    start_Flag = True
                    audio_device= {'id': line.strip().split()[0], 'name1': ' '.join(line.strip().split()[1:]), 'name2': ''}
                elif start_Flag:
                    audio_device['name2'] = line.strip()
                    audio_device_list.append(audio_device)
                    audio_device = {}
                    start_Flag = False
            for audio_device in audio_device_list:
                logging.info('   ID:{} {} {}'.format(audio_device['id'], audio_device['name1'], audio_device['name2']))
            id_list = [audio_device['id'] for audio_device in audio_device_list]
            for i in range(5):
                choice = input('INFO     Which sound card do you want to configure to use? Press the ID and Enter, or press n and enter to ignore this step: ')
                if choice in ['n']:
                    logging.warning('You selected n, ignore this step.')
                    return
                elif choice not in id_list:
                    logging.warning('{} is not in sound card list: {}'.format(choice, str(id_list)))
                else:
                    logging.info('Starting to configure sound card {}'.format(choice))
                    self.run_host_cmd('''sudo sh -c "echo 'defaults.pcm.card {}\ndefaults.ctl.card {}' > /etc/asound.conf"'''.format(choice, choice))
                    self.run_host_cmd('''sudo sh -c "echo 'defaults.pcm.card {}\ndefaults.ctl.card {}' > /home/wid/.asoundrc"'''.format(choice, choice))
                    (output1, err1) = self.run_host_cmd('cat /etc/asound.conf')
                    logging.debug(output1)
                    (output2, err2) = self.run_host_cmd('cat /home/wid/.asoundrc')
                    logging.debug(output2)
                    if 'defaults.pcm.card {}'.format(choice) in output1 and 'defaults.pcm.card {}'.format(choice) in output2 \
                            and 'defaults.ctl.card {}'.format(choice) in output1 and 'defaults.ctl.card {}'.format(choice) in output2:
                        logging.info('Configure sound card finished.')
                    else:
                        logging.error('Configure sound card failed: ')
                        logging.error('/etc/asound.conf: '+output1)
                        logging.error('/home/wid/.asoundrc: '+output2)
                    break
            if i >= 5:
                logging.warning('retype extened maxinum number, ignore this step.')
        self.run_host_cmd("ps -ef|grep speaker-test|grep -v grep|awk '{print \$2}'|xargs kill -9")
        # print('='*20+'{:=<{width}}'.format(' Step 3. finished. ', width=80))
        logging.info('Step 6.3 finished.')
    
    def configure_keyboard_mouse_for_container(self):
        #print('-'*20+'{:60s}'.format('Step 2. configure keyboard and mouse for container')+'-'*20)
        print('='*20+'{:=<{width}}'.format(' Step 6.4. configure keyboard and mouse for container ', width=80))
        input_device_list = self.get_input_device_list()
        keyboards = []
        mouses = []
        for input_device in input_device_list:
            if 'Classes' in input_device and input_device['Classes'] == 'KEYBOARD | ALPHAKEY | EXTERNAL' \
                    and input_device['vendor'] is not None and input_device['product'] is not None:
                keyboards.append(input_device)
            elif 'Classes' in input_device and input_device['Classes'] == 'CURSOR | EXTERNAL' \
                    and input_device['vendor'] is not None and input_device['product'] is not None:
                mouses.append(input_device)

        if not mouses:
            logging.warning('Not detect Mouse device connected to the IVI board.')
        if not keyboards:
            logging.warning('Not detect Keyboard device connected to the IVI board.')

        selected_mouses = self.select_input_device(mouses, 'Mouse', 1)
        selected_keyboards = self.select_input_device(keyboards, 'Keyboard', 1)
        disable_device_ids = None
        if selected_mouses and selected_keyboards:
            disable_device_ids = '{}:{},{}:{}'.format(selected_mouses[0]['vendor'], selected_mouses[0]['product'], selected_keyboards[0]['vendor'], selected_keyboards[0]['product'])
        elif selected_mouses:
            disable_device_ids = '{}:{}'.format(selected_mouses[0]['vendor'], selected_mouses[0]['product'])
        elif selected_keyboards:
            disable_device_ids = '{}:{}'.format(selected_keyboards[0]['vendor'], selected_keyboards[0]['product'])
        else:
            logging.warning('No keyboard and Mouse to be isolated for container.')

        if disable_device_ids:
            logging.info('Starting to disable the device(s) from Android host')
            self.run_host_cmd(self._adb + 'shell "setprop persist.sys.disable.deviceid {}"'.format(disable_device_ids))
            (output, err) = self.run_host_cmd(self._adb + 'shell getprop persist.sys.disable.deviceid')
            if disable_device_ids in output:
                logging.debug(output.strip())
                logging.info('Configuration for isolating the device(s) from Android host successfully.')
            else:
                logging.error('Configuration for isolating the device(s) from Android host failed:')
                logging.error(output) if output else ''
                logging.error(err) if err else ''
        # print('='*20+'{:=<{width}}'.format(' Step 2. finished. ', width=80))
        logging.info('Step 6.4 finished.')

    def download_install_openvino(self):
        print('='*20+'{:=<{width}}'.format(' Step 6.8. Download OpenVino from Ubuntu 22.04 and build OpenVino samples ', width=80))
        logging.info('Tring to get openvino_opencv_build.tar.gz...')
        # (output, err) = self.run_host_cmd('sudo apt install -y wget ssh && echo "package install successfully."')
        # logging.debug(output+err)
        # if 'package install successfully.' not in output:
        #     logging.warning('Install wget ssh failed: {}'.format(output+err))
        logging.info('Please type the wget url or location of openvino_opencv_build.tar.gz/lib_tbb.tar.gz or press n and Enter to ignore this step:')
        url = input('INFO     [wget url/local path/n] ')
        if url in ['n']:
            logging.warning('You selected n, ignore this step.')
            return
        if os.path.isfile(url) and url.endswith('openvino_opencv_build.tar.gz'):
            logging.info('You input a local location for openvino packages, no need to wget')
            openvino_name = url
            libtbb_name = url.replace('openvino_opencv_build.tar.gz', 'lib_tbb.tar.gz')
        else:
            openvino_name = '/home/wid/openvino_opencv_build.tar.gz'
            libtbb_name = '/home/wid/lib_tbb.tar.gz'
            logging.info('It is not a local file, start to download OpenVino packages from url:')
            logging.info('{}'.format(url))
            (output, err) = self.run_host_cmd('rm -rf {} && wget -O {} {} && echo "run host command successfully."'.format(openvino_name, openvino_name, url))
            logging.debug(output+err)
            if 'run host command successfully.' not in output:
                logging.error('wget {} failed, please make sure the openvino_opencv_build.tar.gz can be wget in container'.format(url))
                raise Exception(output+err)
            (output, err) = self.run_host_cmd('rm -rf {} && wget -O {} {} && echo "run host command successfully."'.format(libtbb_name, libtbb_name, url.replace('openvino_opencv_build.tar.gz', 'lib_tbb.tar.gz')))
            logging.debug(output+err)
            if 'run host command successfully.' not in output:
                logging.error('wget {} failed, please make sure the lib_tbb.tar.gz can be wget in container'.format(url.replace(openvino_name, libtbb_name)))
                raise Exception(output+err)
        logging.info('Starting to extract lib_tbb.tar.gz and copy lib_tbb/* to /usr/lib/x86_64-linux-gnu/')
        (output, err) = self.run_host_cmd('rm -rf /home/wid/lib_tbb && tar -zxvf {} -C /home/wid/ && sudo cp /home/wid/lib_tbb/* /usr/lib/x86_64-linux-gnu/ && echo "run host command successfully."'.format(libtbb_name))
        logging.debug(output+err)
        if 'run host command successfully.' not in output:
            raise Exception(output+err)
        logging.info('Starting to extract {}...'.format(openvino_name))
        (output, err) = self.run_host_cmd('rm -rf /home/wid/ov_oc && tar -zxvf {} -C /home/wid/ && echo "run host command successfully."'.format(openvino_name))
        logging.debug(output+err)
        if 'run host command successfully.' not in output:
            raise Exception(output+err)
        #logging.info('Starting to update /etc/apt/sources.list in order to run apt-get update'.format(openvino_name, 'sources.list'))
        #(output, err) = self.run_host_cmd('sudo cp /etc/apt/sources.list /etc/apt/sources.list.orig && sudo wget -O /etc/apt/sources.list {} && echo "run host command successfully."'.format(url.replace(openvino_name, 'sources.list')))
        #logging.debug(output+err)
        logging.info('Starting to install openvino dependencies...')
        (output, err) = self.run_host_cmd('''sed -i "s/apt-get install/apt-get install -y/g" /home/wid/ov_oc/install_dependencies/install_openvino_dependencies.sh && echo "run host command successfully."''', timeout=300)
        logging.debug(output+err)
        (output, err) = self.run_host_cmd('''/bin/bash -c "cd /home/wid/ov_oc && source setupvars.sh && cd /home/wid/ov_oc/install_dependencies && sudo -E ./install_openvino_dependencies.sh && echo 'run host command successfully.'"''', timeout=300)
        logging.debug(output+err)
        if 'run host command successfully.' not in output:
            logging.error('install openvino dependencies failed, please make sure the apt and network works properly in container')
            raise Exception(output+err)
        logging.info('Starting to build OpenVino samples...')
        (output, err) = self.run_host_cmd('''/bin/bash -c "cd /home/wid/ov_oc && source setupvars.sh && cd /home/wid/ov_oc/samples/cpp/ && rm -rfd build && mkdir build && cd build && cmake .. -DOpenCV_DIR="home/wid/ov_oc/build_opencv/" -DOpenCL_LIBRARY=/usr/lib/x86_64-linux-gnu -DOpenCL_INCLUDE_DIR=/usr/include && echo 'run host command successfully.'"''', timeout=300)
        logging.debug(output+err)
        if 'run host command successfully.' not in output:
            raise Exception(output+err)
        (output, err) = self.run_host_cmd('''/bin/bash -c "cd /home/wid/ov_oc && source setupvars.sh && cd /home/wid/ov_oc/samples/cpp/build && make -j5 && echo 'run host command successfully.'"''', timeout=400)
        logging.debug(output+err)
        if 'run host command successfully.' not in output:
            raise Exception(output+err)
        logging.info('Openvino installation finished. You can run samples with following steps:') 
        logging.info('$ cd intel64/')
        logging.info('$ ./hello_query_device')
        logging.info('this should list dGPU as one of the devices like:')
        logging.info('    "Immutable: DEVICE_ARCHITECTURE : GPU.12.7.1')
        logging.info('    [ INFO ]                Immutable: FULL_DEVICE_NAME : Intel(R) Graphics [0x56c0] (dGPU)"')
        logging.info('Try running benchmark app')
        logging.info('$ ./benchmark_app -m <path-to-ir-xml-model> -d GPU')
        logging.info('Step 6.8 finished.')
    
    def install_resources(self):
        print('='*20+'{:=<{width}}'.format(' Step 3. install resources for demo ', width=80))
        # print('='*20+'{:=<{width}}'.format(' Step 3. finished. ', width=80))
        logging.info('Step 3 finished.')
    
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
    
    def get_input_device_list(self):
        (output, err) = self.run_host_cmd(self._adb + 'shell dumpsys input')
        input_device_list = []
        input_device = None
        for line in output.split('\n'):
            if line.strip().startswith('Input Reader State'):
                break
            sl = line.strip().split(':')
            if len(sl) < 2:
                continue
            if sl[0].isdigit() or sl[0].lstrip('-').isdigit():
                input_device = {
                    'ID': int(sl[0]),
                    'Name': sl[1].strip(),
                }
            elif input_device is not None and sl[0] == 'VideoDevice':
                input_device['VideoDevice'] = sl[1]
                input_device_list.append(input_device)
                input_device = None
            elif input_device is not None:
                input_device[sl[0]] = ':'.join(sl[1:]).strip()

        for input_device in input_device_list:
            (vendor, product) = self.get_vendor_product(input_device)
            input_device['vendor'] = vendor
            input_device['product'] = product
        logging.debug('input_device_list:')
        logging.debug(str(input_device_list))
            
        return input_device_list

    def get_vendor_product(self, input_device):
        vendor = None
        product = None
        if 'Identifier' in input_device:
            for item in input_device['Identifier'].split(','):
                si = item.split('=')
                if len(si) == 2 and si[0].strip() == 'vendor':
                    vendor = si[1].strip()[2:]
                elif len(si) == 2 and si[0].strip() == 'product':
                    product = si[1].strip()[2:]
        return (vendor, product)

    def get_display_info_list(self):
        # (output, err) = self.run_host_cmd(self._adb + 'shell dumpsys SurfaceFlinger --display-id')
        # re_display_id = re.compile('Display (\d+) \((.*)\): port=(\d+) pnpId=(.*) displayName="(.*)"')
        # for line in output.split('\n'):
        #     s = re.search(re_display_id, line)
        #     if s and len(s.groups()) == 5:
        #         pass
        (output, err) = self.run_host_cmd(self._adb + 'shell dumpsys input')
        display_info_flag = False
        display_info_list = []
        display_info = {}
        '''re_viewport = re.compile('displayId=(\d+), uniqueId=(.*), port=(\d+), orientation=(\d+), logicalFrame')
        for line in output.split('\n'):
            if line.strip().startswith('Input Reader State'):
                display_info_flag = True
            elif line.strip() == 'Configuration:':
                display_info_flag = False
                break
            elif line.strip().startswith('Device ') and display_info_flag:
                display_info = {'Name': line.strip().split(':')[1] if len(line.strip().split(':'))>1 else ''}
            elif line.strip().startswith('EventHub Devices:') and display_info_flag:
                if display_info:
                    display_info['devices'] = line.strip().split(':')[1].strip()[1:-1].split()
            elif line.strip().startswith('DeviceType:') and display_info_flag:
                if 'TOUCH' not in line:
                    display_info = {}
                    logging.debug('NO TOUCH!!!!!!!')
                    logging.debug(line)
                if display_info:
                    display_info['DeviceType'] = line.strip().split(':')[1]
            elif line.strip().startswith('Viewport INTERNAL:') and display_info_flag:
                if not display_info:
                    continue
                s = re.search(re_viewport, line.strip())
                if s and len(s.groups()) == 4:
                    display_info['displayId'] = s.group(1)
                    display_info['uniqueId'] = s.group(2)
                    display_info['port'] = s.group(3)
                    display_info['orientation'] = s.group(4)
                else:
                    display_info['displayId'] = ''
                    display_info['uniqueId'] = ''
                    display_info['port'] = ''
                    display_info['orientation'] = ''
                if 'devices' in display_info and display_info['devices']:
                    display_info_list.append(display_info)
                display_info = {}
        logging.debug('display_info_list')
        logging.debug(str(display_info_list))
        return display_info_list'''

        for line in output.split('\n'):
            if line.strip() == 'Configuration:':
                display_info_flag = True
            if display_info_flag:
                if line.strip().startswith('Input Classifier State:') or line.strip().startswith('Input Dispatcher State:'):
                    break
                if line.strip().startswith('Viewport INTERNAL:') or line.strip().startswith('Viewport EXTERNAL:'):
                    display_info_list.append({'Viewport': line.strip()[18:]})
                continue
        re_viewport = re.compile('displayId=(\d+), uniqueId=(.*), port=(\d+), orientation=(\d+), logicalFrame=(.*), physicalFrame=(.*), deviceSize=(.*)')
        for display_info in display_info_list:
            viewport = display_info['Viewport']
            s = re.search(re_viewport, viewport.strip())
            if s and len(s.groups()) == 7:
                display_info['displayId'] = s.group(1)
                display_info['uniqueId'] = s.group(2)
                display_info['port'] = s.group(3)
                display_info['orientation'] = s.group(4)
                display_info['logicalFrame'] = s.group(5)
                display_info['physicalFrame'] = s.group(6)
                display_info['deviceSize'] = s.group(7)
            else:
                display_info['displayId'] = ''
                display_info['uniqueId'] = ''
                display_info['port'] = ''
                display_info['orientation'] = ''
                display_info['logicalFrame'] = '' 
                display_info['physicalFrame'] = ''
                display_info['deviceSize'] = ''
        logging.debug('display_info_list')
        logging.debug(str(display_info_list))
        return display_info_list
        # new_list = []
        # for display_info in display_info_list:
        #     new_id_list = [i['displayId'] for i in new_list if 'displayId' in i]
        #     if display_info['displayId'] not in new_id_list:
        #         new_list.append(display_info)
        # return new_list

    def plugin_detect_input_device(self, device, device_class, dest):
        input_device = None
        PLUGIN_DETECT_RETRY_TIMES = 10
        PLUGIN_WAIT_TIME = 60
        new_input_device = None
        for i in range(PLUGIN_DETECT_RETRY_TIMES):
            input_device_list = self.get_input_device_list()
            path_list = [input_device['Path'] for input_device in input_device_list if 'Path' in input_device]
            display_id_list = []
            if 'TOUCH' in device_class:
                display_info_list = get_display_ids()
                display_id_list = [display_info['ID'] for display_info in display_info_list if 'ID' in display_info]
            choice = input('Are you going to plug in the {} for {}? [y/n]'.format(device, dest))
            if choice in ['n']:
                logging.info('You selected n, so no device to configure')
                return input_device
            elif choice in ['y']:
                logging.info('You selected y, please plug in the {}, and the script will wait for at most {} seconds to detect the device'.format(device, PLUGIN_WAIT_TIME))
                new_input_device_list = []
                new_display_info_list = []
                for j in range(PLUGIN_WAIT_TIME):
                    time.sleep(1)
                    input_device_list2 = self.get_input_device_list()
                    new_input_device_list = []
                    for input_device in input_device_list2:
                        if 'Path' in input_device and input_device['Path'] not in path_list \
                                and 'Class' in input_device and input_device['Class'] == device_class:
                            new_input_device_list.append(input_device)
                    if 'TOUCH' in device_class:
                        display_info_list2 = get_display_ids()
                        new_display_info_list = []
                        for display_info in display_info_list2:
                            if 'ID' in display_info and display_info['ID'] not in display_id_list:
                                new_display_info_list.append(display_info)
                        if not new_input_device_list or not new_display_info_list:
                            logging.info('Detecting {} device to plug in ...'.format(device))
                            new_input_device_list = []
                            new_display_info_list = []
                        elif len(new_input_device_list) > 1 or len(new_display_info_list) > 1:
                            logging.warning('Detected more than 1 device plugged in, please keep only 1 device and remove the addition device(s)...')
                            new_input_device_list = []
                            new_display_info_list = []
                            time.sleep(5)
                        elif len(new_input_device_list) == 1 and len(new_display_info_list) == 1:
                            break
                        else:
                            logging.info('Detecting {} device to plug in ...'.format(device))
                            new_input_device_list = []
                            new_display_info_list = []
                    else:
                        if not new_input_device_list:
                            logging.info('Detecting {} device to plug in ...'.format(device))
                            continue
                        elif len(new_input_device_list) > 1:
                            logging.warning('Detected more than 1 device plugged in, please keep only 1 device and remove the addition device(s)...')
                            new_input_device_list = []
                            time.sleep(5)
                        else:
                            break
                
                if new_input_device_list:
                    logging.info('Detected 1 {} device plugged in: {}.{}'.format(device, new_input_device_list[0]['ID'], new_input_device_list[0]['Name']))
                    new_input_device = new_input_device_list[0]
                    if 'TOUCH' in device_class and new_display_info_list:
                        new_input_device['DisplayInfo': new_display_info_list[0]]
                    break
                else:
                    logging.warning('Not detected 1 new {} device plugged in for {} seconds'.format(device, PLUGIN_WAIT_TIME))
            else:
                logging.warning('Unsupported choice, please type y or n')

            return new_input_device

    def select_input_device(self, input_device_list, device_type, num):
        selected_input_devices = []
        if len(input_device_list) <= num and len(input_device_list) > 0:
            logging.info('Detected {} {} device(s)'.format(len(input_device_list), device_type))
            for input_device in input_device_list:
                logging.info('    ID: {}  Name: {}'.format(input_device['ID'], input_device['Name']))
            logging.info('Select the detected {} {} device(s) isolated for container'.format(len(input_device_list), device_type))
            selected_input_devices = input_device_list
        elif len(input_device_list) > num:
            select_msg = 'INFO    Detected more than {} {} device.\nWhich {} to be configured to docker container? Type device ID and Enter to select or press Enter to select the first one:\n'.format(num, device_type, device_type)
            for input_device in input_device_list:
                select_msg += '        ID:{}  Name:{}  Location:{}  Identifier:{}\n'.format(input_device['ID'], input_device['Name'], input_device['Location'], input_device['Identifier'])
            select_msg += 'INFO    Type ID(s): '
            id_list = [input_device_list['ID'] for input_device in input_device_list]
            selected_ids = []
            for i in range(10):
                ids = input(select_msg)
                selected_ids = []
                if sid == '':
                    selected_ids = id_list[:num]
                    logging.info('Selected the first {} device(s) by default.'.format(num))
                    break
                sids = ids.split(',')
                for sid in sids:
                    if sid.strip() in id_lists:
                        selected_ids.append(sid.strip())
                if len(selected_ids) == num:
                    logging.info('Selected device ID(s): {}'.format(','.join(selected_ids)))
                    break
                else:
                    logging.info('Unsupported choice, please type {} device ID(s) and press Enter or press Enter: '.format(num))
            if i == 10:
                logging.info('Extended maximum choices, select the first {} device(s) by default.'.format(num))
                selected_ids = id_list[:num]
            
            for input_device in input_device_list:
                if input_device['ID'] in selected_ids:
                    selected_input_devices.append(input_device)
        return selected_input_devices

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
    
    parser = argparse.ArgumentParser(description='IVI POC Demo config tool')
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
    configed = False
    # configed = config.config_docker_proxy()
    if not configed:
        config.configure_touch_for_android()
        config.configure_keyboard_mouse_for_container()
        config.enable_multiple_hardware_plan()
        config.configure_audio()
        config.download_install_openvino()
        # config.install_resources()
    config.reboot_android()
    print('='*20+'{:=<{width}}'.format(' ALL DONE ', width=80))


