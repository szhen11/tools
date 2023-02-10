# -*- coding: utf-8 -*-
"""IVI POC Demo config tool.

This tool is used to auto configure IVI POC Demo touch/keyboard/mouse related configs.

Precondition: 
    log into container of android: docker exec -it steam bash
    apt-get install python3 git adb
    git clone https://github.com/szhen11/tools.git
    cd tools/ivi/

Execution:
    python3 demo_config.py [-i android_ip]

Author: shuang.zheng@intel.com

Modified:

"""
import os, time, argparse, subprocess
import re, traceback, logging, datetime, ipaddress

class ConfigureInputDevice():
    def __init__(self, outputdir='.'):
        self._adb = 'adb '
        self._outputdir = outputdir

    def setup_adb_connection(self, ip):
        print('='*20+'{:=<{width}}'.format(' Step 0. setup Adb connection with Android ', width=80))
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

    def configure_touch_for_android(self):
        # print('-'*20+'{:60s}'.format('Step 1. enable multiple touch screen(s) for Android')+'-'*20)
        print('='*20+'{:=<{width}}'.format(' Step 1. enable multiple touch screen(s) for Android ', width=80))
        logging.info('Please make sure the touch screen(s) connected to the iGPU before this configuration step!')
        TOUCH_DETECT_RETRY_TIMES = 10
        touch_device_list = []
        input_device_list = self.get_input_device_list()
        display_info_list = self.get_display_info_list()
        index = 0
        for display_info in display_info_list:
            index += 1
            for i in range(TOUCH_DETECT_RETRY_TIMES):
                print('-'*20+'{:-<{width}}'.format('Step 1.{}. detect the touch screen for Display {}'.format(index, display_info['displayId']), width=80))
                logging.info('Start to detect touch screen for Display: Id={} uniqueId={} ...'.format(display_info['displayId'], display_info['uniqueId']))
                logging.info('Launching Settings Application on Display {}'.format(display_info['displayId']))
                self.run_host_cmd('{} shell am force-stop com.android.car.settings'.format(self._adb))
                self.run_host_cmd('{} shell am start --user 10 --display {} com.android.car.settings'.format(self._adb, display_info['displayId']))
                self.run_host_cmd(self._adb + 'shell rm -rf /data/local/getevent.log')
                self.run_host_cmd(self._adb + 'shell "getevent > /data/local/getevent.log 2>&1 &"')
                logging.info('Please touch the screen which launching Setting Application, and then press Enter to continue;')
                print('         Or press n and Enter to ignore this step 1.{} if the screen which launching Setting App is untouchable: '.format(index))
                choice = input('INFO     [y/n] ')
                if choice == 'n':
                    logging.info('You selected n, ignore Step 1.{}.'.format(index))
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
                            # if input_device['Path'] == event and 'TOUCH | TOUCH_MT | EXTERNAL' in input_device['Classes']:
                            if input_device['Path'] == event and 'TOUCH' in input_device['Classes']:
                                touch_device = input_device
                                break
                    if touch_device:
                        logging.info('Detected current touch screen {}, start to create idc file for it'.format(touch_device['Name']))
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

        if len(touch_device_list) == 2 \
                and touch_device_list[0][1]['vendor'] == touch_device_list[1][1]['vendor'] \
                and touch_device_list[0][1]['product'] == touch_device_list[1][1]['product']:
            # Creating idc file for 2 touch devices with same manufacturers 
            for touch_device in touch_device_list:
                display_info = touch_device[0]
                touch_screen = touch_device[1]
                logging.info('Start to create idc file for touch screen: {}. {}'.format(display_info['displayId'], touch_screen['Name']))
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
                    logging.info('Creating idc file for Touch Display {} successfully.'.format(display_info['displayId']))
                else:
                    logging.error('Creating idc file for Touch Display {} failed.'.format(display_info['displayId']))
                    logging.error(output) if output else ''
                    logging.error(err) if err else ''
        else:
            for touch_device in touch_device_list:
                display_info = touch_device[0]
                touch_screen = touch_device[1]
                logging.info('Start to create idc file for touch screen: {}.{}'.format(display_info['displayId'], touch_screen['Name']))
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
                    logging.info('Creating idc file for Touch Display {} successfully.'.format(display_info['displayId']))
                else:
                    logging.error('Creating idc file for Touch Display {} failed.'.format(display_info['displayId']))
                    logging.error(output) if output else ''
                    logging.error(err) if err else ''
        # print('='*20+'{:=<{width}}'.format(' Step 1. finished.', width=80))
        logging.info('Step 1 finished.')
    
    def configure_keyboard_mouse_for_container(self):
        #print('-'*20+'{:60s}'.format('Step 2. configure keyboard and mouse for container')+'-'*20)
        print('='*20+'{:=<{width}}'.format(' Step 2. configure keyboard and mouse for container ', width=80))
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
            logging.info('Start to disable the device(s) from Android host')
            self.run_host_cmd(self._adb + 'shell "setprop persist.sys.disable.deviceid {}"'.format(disable_device_ids))
            (output, err) = self.run_host_cmd(self._adb + 'shell getprop persist.sys.disable.deviceid')
            if disable_device_ids in output:
                logging.debug(output)
                logging.info('Configuration for isolating the device(s) from Android host successfully.')
            else:
                logging.error('Configuration for isolating the device(s) from Android host failed:')
                logging.error(output) if output else ''
                logging.error(err) if err else ''
        logging.info('Update udev rules to ignore the keyboard/mouse which are not isolated to container.')
        multi_flag = False
        ignore_mouse_file_name = '99-ignore-mouses.rules'
        if(len(selected_mouses)<len(mouses)):
            s_ids = [m['ID'] for m in selected_mouses]
            remain_mouse = None
            for mouse in mouses:
                if (mouse['ID'] not in s_ids) and mouse['vendor'] and mouse['product']:
                    remain_mouse = mouse
                    break
            if remain_mouse is not None:
                multi_flag = True
                logging.debug('disable the other mouse in container: {}'.format(remain_mouse['Name']))
                with open(os.path.join(self._outputdir, ignore_mouse_file_name), 'w') as f:
                    f.write('ACTION=="add|change", KERNEL=="event[0-9]*", \\\n')
                    f.write('   ENV{{ID_VENDOR_ID}}=="{}", \\\n'.format(remain_mouse['vendor']))
                    f.write('   ENV{{ID_MODEL_ID}}=="{}", \\\n'.format(remain_mouse['product']))
                    f.write('   ENV{{LIBINPUT_IGNORE_DEVICE}}="1"')
                self.run_host_cmd('sudo cp {} /etc/udev/rules.d/'.format(os.path.join(self._outputdir, ignore_mouse_file_name)))
        if not multi_flag:
            logging.debug('No other mouse need to be disabled in container')
            with open(os.path.join(self._outputdir, ignore_mouse_file_name), 'w') as f:
                f.write('ACTION=="add|change", KERNEL=="event[0-9]*", \\\n')
                f.write('   ENV{{ID_VENDOR_ID}}=="{}", \\\n'.format('0000'))
                f.write('   ENV{{ID_MODEL_ID}}=="{}", \\\n'.format('0000'))
                f.write('   ENV{{LIBINPUT_IGNORE_DEVICE}}="1"')
            self.run_host_cmd('sudo cp {} /etc/udev/rules.d/'.format(os.path.join(self._outputdir, ignore_mouse_file_name)))
        multi_flag = False
        ignore_keyboard_file_name = '99-ignore-keyboards.rules'
        if(len(selected_keyboards)<len(keyboards)):
            s_ids = [k['ID'] for k in selected_keyboards]
            remain_keyboard = None
            for keyboard in keyboards:
                if (keyboard['ID'] not in s_ids) and keyboard['vendor'] and keyboard['product']:
                    remain_keyboard = keyboard
                    break
            if remain_keyboard is not None:
                multi_flag = True
                logging.debug('disable the other keyboard in container: {}'.format(remain_keyboard['Name']))
                with open(os.path.join(self._outputdir, ignore_keyboard_file_name), 'w') as f:
                    f.write('ACTION=="add|change", KERNEL=="event[0-9]*", \\\n')
                    f.write('   ENV{{ID_VENDOR_ID}}=="{}", \\\n'.format(remain_keyboard['vendor']))
                    f.write('   ENV{{ID_MODEL_ID}}=="{}", \\\n'.format(remain_keyboard['product']))
                    f.write('   ENV{{LIBINPUT_IGNORE_DEVICE}}="1"')
                self.run_host_cmd('sudo cp {} /etc/udev/rules.d/'.format(os.path.join(self._outputdir, ignore_keyboard_file_name)))
        if not multi_flag:
            logging.debug('No other mouse need to be disabled in container')
            with open(os.path.join(self._outputdir, ignore_keyboard_file_name), 'w') as f:
                f.write('ACTION=="add|change", KERNEL=="event[0-9]*", \\\n')
                f.write('   ENV{{ID_VENDOR_ID}}=="{}", \\\n'.format('0000'))
                f.write('   ENV{{ID_MODEL_ID}}=="{}", \\\n'.format('0000'))
                f.write('   ENV{{LIBINPUT_IGNORE_DEVICE}}="1"')
            self.run_host_cmd('sudo cp {} /etc/udev/rules.d/'.format(os.path.join(self._outputdir, ignore_keyboard_file_name)))

        # print('='*20+'{:=<{width}}'.format(' Step 2. finished. ', width=80))
        logging.info('Step 2 finished.')

    def install_resources(self):
        print('='*20+'{:=<{width}}'.format(' Step 3. install resources for demo ', width=80))
        # print('='*20+'{:=<{width}}'.format(' Step 3. finished. ', width=80))
        logging.info('Step 3 finished.')
    
    def reboot_android(self):
        print('='*20+'{:=<{width}}'.format('  Step 4. reboot Android to make the configuration effetctive', width=80))
        choice = input('INFO     Do you want to adb reboot Android to make the configuration effective? [y/n] ')
        if 'y' in choice:
            self.run_host_cmd(self._adb + 'reboot')
        else:
            logging.info('Ignore this step, please reboot Android by yourself.')
        # print('{:=<{width}}'.format(' Step 4. adb reoboot finished. ', width=80))
        logging.info('Step 4 finished.')
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
        (output, err) = self.run_host_cmd(self._adb + 'shell dumpsys input')
        display_info_flag = False
        display_info_list = []
        for line in output.split('\n'):
            if line.strip() == 'Configuration:':
                display_info_flag = True
            if display_info_flag:
                if line.strip().startswith('Input Classifier State:') or line.strip().startswith('Input Dispatcher State:'):
                    break
                if line.strip().startswith('Viewport INTERNAL:'):
                    display_info_list.append({'Viewport': line.strip()[18:]})
                continue
        re_viewport = re.compile('displayId=(\d+), uniqueId=(.*), port=(\d+), orientation=(\d+), logicalFrame')
        for display_info in display_info_list:
            viewport = display_info['Viewport']
            s = re.search(re_viewport, viewport.strip())
            if s and len(s.groups()) == 4:
                display_info['displayId'] = s.group(1)
                display_info['uniqueId'] = s.group(2)
                display_info['port'] = s.group(3)
                display_info['orientation'] = s.group(4)
        logging.debug('display_info_list')
        logging.debug(str(display_info_list))
        return display_info_list

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
            select_msg = 'INFO     Detected more than {} {} device.         \nWhich {} to be configured to docker container? Type device ID and Enter to select or press Enter to select the first {}:\n'.format(num, device_type, device_type, num)
            for input_device in input_device_list:
                select_msg += '         ID:{}  Name:{}  Location:{}  Identifier:{}\n'.format(input_device['ID'], input_device['Name'], input_device['Location'], input_device['Identifier'])
            select_msg += 'INFO     Type ID(s): '
            id_list = [input_device['ID'] for input_device in input_device_list]
            selected_ids = []
            for i in range(10):
                ids = input(select_msg)
                selected_ids = []
                if ids == '':
                    selected_ids = id_list[:num]
                    logging.info('Selected the first {} device(s) by default.'.format(num))
                    break
                sids = ids.split(',')
                for sid in sids:
                    if sid.strip().isdigit() and int(sid.strip()) in id_list:
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
                if str(input_device['ID']) in selected_ids:
                    selected_input_devices.append(input_device)
        return selected_input_devices

    def verify_adb(self):
        (output, err) = self.run_host_cmd('adb devices')
        if 'List of devices attached' not in output:
            msg = 'adb not installed properly, please install adb before configuration.'
            logging.error(msg)
            raise Exception(msg)

    def run_host_cmd(self, cmd):
        output = ''
        errmsg = ''
        try:
            logging.debug('Run host command: {}'.format(cmd))
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, timeout=30).decode("utf-8")
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
    
    parser = argparse.ArgumentParser(description='configure demo setup.')
    parser.add_argument("-i", "--ip", dest="ip", default=None,
                    help="IP Address of Android")
    parser.add_argument("-o", "--outputdir", dest="outputdir", default=outputdir,
                    help="the directory to store logs")
    args = parser.parse_args()

    os.makedirs(outputdir)
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)-8s %(message)s",
        handlers=[
            logging.FileHandler("{0}/{1}.log".format(outputdir, 'execution')),
            logging.StreamHandler()
        ]
    )

    config = ConfigureInputDevice(args.outputdir)
    config.setup_adb_connection(args.ip)
    config.configure_touch_for_android()
    config.configure_keyboard_mouse_for_container()
    config.install_resources()
    config.reboot_android()
    print('='*20+'{:=<{width}}'.format(' ALL DONE ', width=80))


