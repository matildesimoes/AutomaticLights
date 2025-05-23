import asyncio
import json
import argparse
import logging
import time
import requests
import re
from bleak import BleakScanner

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/tmp/bt_uuid_scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BT-UUID-Scanner")

class UUIDBluetoothScanner:
    def __init__(self, target_devices=None, hass_url=None, hass_token=None):
        """
        Initialize the Bluetooth Scanner with UUID detection.
        
        Args:
            target_devices (dict): Dictionary mapping UUIDs to device names
            hass_url (str): Home Assistant URL
            hass_token (str): Long-lived access token for Home Assistant
        """
        self.target_devices = target_devices or {}
        self.hass_url = hass_url.rstrip('/') if hass_url else None
        self.hass_token = hass_token
        
        logger.info(f"Initialized scanner with {len(self.target_devices)} target devices")
    
    def classify_rssi(self, rssi):
        """
        Classify RSSI signal strength.
        
        Args:
            rssi (int): RSSI value in dBm
            
        Returns:
            str: Signal quality classification
        """
        if rssi >= -50:
            return "Excellent"
        elif rssi >= -60:
            return "Good"
        elif rssi >= -70:
            return "Fair"
        elif rssi >= -80:
            return "Weak"
        elif rssi >= -90:
            return "Very Weak"
        else:
            return "Unusable"
    
    def extract_uuid_from_mfr_data(self, mfr_data):
        """
        Extract UUIDs from manufacturer data.
        
        Args:
            mfr_data (dict): Manufacturer data
            
        Returns:
            set: Set of UUIDs found in the data
        """
        uuids = set()
        
        for company_id, data in mfr_data.items():
            try:
                if isinstance(data, (bytes, bytearray)):
                    hex_data = data.hex()
                else:
                    hex_data = str(data)
                
                if len(hex_data) >= 32: 
                    if company_id == 76 and hex_data.startswith('0215'):
                        uuid_part = hex_data[4:36]
                        
                        uuid = f"{uuid_part[0:8]}-{uuid_part[8:12]}-{uuid_part[12:16]}-{uuid_part[16:20]}-{uuid_part[20:32]}"
                        uuids.add(uuid.lower())
                        
                        uuids.add(uuid_part.lower())
                    
                    uuid_matches = re.findall(r'([0-9a-fA-F]{8}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{12})', hex_data)
                    for match in uuid_matches:
                        uuid = f"{match[0:8]}-{match[8:12]}-{match[12:16]}-{match[16:20]}-{match[20:32]}"
                        uuids.add(uuid.lower())
                        
                        uuids.add(match.lower())
            except Exception as e:
                logger.debug(f"Error extracting UUID from manufacturer data: {e}")
        
        return uuids
    
    async def scan_for_devices(self, scan_time=10.0):
        """
        Scan for BLE devices using Bleak.
        
        Args:
            scan_time (float): Time in seconds to scan for devices
            
        Returns:
            tuple: (all_devices, target_devices) - dictionaries of all detected devices and target devices
        """
        all_devices = {}
        target_devices_found = {}
        
        def detection_callback(device, advertisement_data):
            """Callback function for device detection."""
            addr = device.address
            addr_lower = addr.lower()
            
            if addr_lower in all_devices and all_devices[addr_lower]['rssi'] >= advertisement_data.rssi:
                return
            
            rssi = advertisement_data.rssi
            signal_quality = self.classify_rssi(rssi)
            
            manufacturer_data = {}
            found_uuids = set()
            
            if advertisement_data.manufacturer_data:
                for key, value in advertisement_data.manufacturer_data.items():
                    try:
                        if isinstance(value, (bytes, bytearray)):
                            manufacturer_data[key] = value.hex()
                        else:
                            manufacturer_data[key] = str(value)
                    except Exception as e:
                        logger.debug(f"Error processing manufacturer data: {e}")
                        manufacturer_data[key] = str(value)
                
                found_uuids.update(self.extract_uuid_from_mfr_data(advertisement_data.manufacturer_data))
            
            device_info = {
                'address': device.address,
                'name': device.name or 'Unknown',
                'rssi': rssi,
                'signal_quality': signal_quality,
                'manufacturer_data': manufacturer_data,
                'uuids': list(found_uuids)
            }
            
            if advertisement_data.service_uuids:
                device_info['service_uuids'] = [str(uuid) for uuid in advertisement_data.service_uuids]
                found_uuids.update([str(uuid).lower() for uuid in advertisement_data.service_uuids])
            
            all_devices[addr_lower] = device_info
            
            for uuid in found_uuids:
                if uuid in self.target_devices:
                    target_name = self.target_devices[uuid]
                    logger.info(f"Target device found by UUID: {target_name} ({uuid}) at {addr}, RSSI: {rssi} dBm")
                    target_devices_found[addr_lower] = {
                        'name': target_name,
                        'uuid': uuid,
                        'address': addr,
                        'rssi': rssi,
                        'signal_quality': signal_quality
                    }
        
        try:
            scanner = BleakScanner(detection_callback=detection_callback)
            
            logger.info(f"Starting BLE scan for {scan_time} seconds...")
            await scanner.start()
            await asyncio.sleep(scan_time)
            await scanner.stop()
            
            logger.info(f"Scan completed. Found {len(all_devices)} total devices, {len(target_devices_found)} target devices")
            
            return all_devices, target_devices_found
            
        except Exception as e:
            logger.error(f"Error during BLE scan: {e}")
            return {}, {}
    
    def send_to_hass(self, device_data):
        """Send device data to Home Assistant via REST API."""
        if not self.hass_url or not self.hass_token:
            logger.warning("Home Assistant URL or token not provided, skipping data send")
            return
        
        headers = {
            "Authorization": f"Bearer {self.hass_token}",
            "Content-Type": "application/json"
        }
        
        for addr, data in device_data.items():
            try:
                device_name = data['name'].lower().replace(' ', '_')
                entity_id = f"sensor.bt_{device_name}"
                
                payload = {
                    "state": data['rssi'],
                    "attributes": {
                        "friendly_name": f"BT {data['name']}",
                        "device_id": addr,
                        "uuid": data.get('uuid', ''),
                        "unit_of_measurement": "dBm", 
                        "device_class": "signal_strength",
                        "signal_quality": data['signal_quality']
                    }
                }
                
                url = f"{self.hass_url}/api/states/{entity_id}"
                response = requests.post(url, headers=headers, json=payload)
                
                if response.status_code in (200, 201):
                    logger.info(f"Successfully updated {entity_id} in Home Assistant")
                else:
                    logger.error(f"Failed to update {entity_id}. Status: {response.status_code}, Response: {response.text}")
            
            except Exception as e:
                logger.error(f"Error sending data to Home Assistant for {addr}: {e}")
    
    def print_devices(self, devices, target_devices):
        """
        Print all detected devices in a formatted way.
        
        Args:
            devices (dict): Dictionary of all detected devices
            target_devices (dict): Dictionary of target devices found
        """
        if not devices:
            print("\nNo Bluetooth devices detected during scan.")
            return
        
        print("\n=== All Detected Bluetooth Devices ===")
        print(f"Total devices found: {len(devices)}")
        print(f"Target devices found: {len(target_devices)}")
        print("-" * 70)
        
        for i, (addr, dev_info) in enumerate(devices.items(), 1):
            is_target = "✓" if addr in target_devices else " "
            target_name = target_devices[addr]['name'] if addr in target_devices else ""
            target_str = f" ({target_name})" if target_name else ""
            
            print(f"{i}. [{is_target}] {dev_info['name']} ({dev_info['address']}){target_str}")
            print(f"   RSSI: {dev_info['rssi']} dBm ({dev_info['signal_quality']})")

            if 'uuids' in dev_info and dev_info['uuids']:
                print(f"   UUIDs: {', '.join(dev_info['uuids'])}")
  
            if 'manufacturer_data' in dev_info and dev_info['manufacturer_data']:
                print(f"   Manufacturer Data: {dev_info['manufacturer_data']}")
            
            print("-" * 70)
    
    def generate_config(self, devices):
        """
        Generate a configuration file from detected devices.
        
        Args:
            devices (dict): Dictionary of detected devices
            
        Returns:
            dict: Configuration dictionary
        """
        uuid_config = {}
        
        for addr, dev_info in devices.items():
            if 'uuids' in dev_info and dev_info['uuids']:
                for uuid in dev_info['uuids']:
                    name = dev_info['name']
                    if name == 'Unknown':
                        name = f"Device_{addr[-5:].replace(':', '')}"
                    uuid_config[uuid] = name
        
        return {"devices": uuid_config}
    
    def print_config_snippet(self, config):
        """
        Print a configuration snippet.
        
        Args:
            config (dict): Configuration dictionary
        """
        if not config["devices"]:
            print("\nNo devices with UUIDs found.")
            return
        
        print("\n=== UUID Configuration Snippet ===")
        print("Copy this to your config file to track devices by UUID:")
        print(json.dumps(config, indent=2))
        print("====================================")
    
    async def run_once(self, scan_time=10.0, send_to_ha=False):
        """
        Run a single scanning cycle.
        
        Args:
            scan_time (float): Time to scan in seconds
            send_to_ha (bool): Whether to send data to Home Assistant
            
        Returns:
            tuple: (all_devices, target_devices) - dictionaries of all detected devices and target devices
        """
        all_devices, target_devices = await self.scan_for_devices(scan_time)
        self.print_devices(all_devices, target_devices)
        
        config = self.generate_config(all_devices)
        self.print_config_snippet(config)
        
        if send_to_ha and target_devices and self.hass_url and self.hass_token:
            self.send_to_hass(target_devices)
        
        return all_devices, target_devices
    
    async def run_continuous(self, interval=30.0, scan_time=10.0):
        """Run continuous detection with specified interval."""
        logger.info(f"Starting continuous detection with {interval}s interval")
        try:
            while True:
                start_time = time.time()
                all_devices, target_devices = await self.scan_for_devices(scan_time)

                logger.info(f"Found {len(all_devices)} total devices, {len(target_devices)} target devices")
                
                if target_devices and self.hass_url and self.hass_token:
                    self.send_to_hass(target_devices)

                elapsed = time.time() - start_time
                sleep_time = max(0, interval - elapsed)
                
                if sleep_time > 0:
                    logger.debug(f"Sleeping for {sleep_time:.2f}s")
                    await asyncio.sleep(sleep_time)
        except asyncio.CancelledError:
            logger.info("Detection cancelled")
        except Exception as e:
            logger.error(f"Error in continuous detection: {e}")

async def main_async():
    parser = argparse.ArgumentParser(description='Bluetooth Scanner with UUID Detection')
    parser.add_argument('--config', help='Path to JSON configuration file')
    parser.add_argument('--interval', type=float, default=30.0, help='Detection interval in seconds')
    parser.add_argument('--scan-time', type=float, default=10.0, help='Time to scan for devices in seconds')
    parser.add_argument('--once', action='store_true', help='Run detection once and exit')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--uuid', action='append', help='Target UUID:NAME pair')
    parser.add_argument('--hass-url', help='Home Assistant URL')
    parser.add_argument('--hass-token', help='Home Assistant long-lived access token')
    parser.add_argument('--no-send', action='store_true', help='Do not send data to Home Assistant')
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    target_devices = {}
    hass_url = None
    hass_token = None
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                if 'devices' in config:
                    target_devices.update(config['devices'])
                
                if not args.no_send and 'hass_url' in config:
                    hass_url = config['hass_url']
                
                if not args.no_send and 'hass_token' in config:
                    hass_token = config['hass_token']
        except Exception as e:
            logger.error(f"Error loading config file: {e}")
            return 1
    
    if args.uuid:
        for uuid_str in args.uuid:
            try:
                uuid, name = uuid_str.split(':', 1)
                target_devices[uuid.lower()] = name
            except ValueError:
                logger.error(f"Invalid UUID format: {uuid_str}. Use UUID:NAME")
                return 1

    if args.hass_url:
        hass_url = args.hass_url
    
    if args.hass_token:
        hass_token = args.hass_token
    
    if args.no_send:
        hass_url = None
        hass_token = None
    
    scanner = UUIDBluetoothScanner(
        target_devices=target_devices,
        hass_url=hass_url,
        hass_token=hass_token
    )
    
    if args.once:
        await scanner.run_once(scan_time=args.scan_time, send_to_ha=not args.no_send)
    else:
        await scanner.run_continuous(interval=args.interval, scan_time=args.scan_time)
    
    return 0

def main():
    """Entry point for the script."""
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nScan cancelled by user")
        return 0

if __name__ == "__main__":
    exit(main())
