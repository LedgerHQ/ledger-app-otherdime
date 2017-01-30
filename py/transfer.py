"""
*******************************************************************************
*   OtherDime : Attestation demonstration
*   (c) 2017 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************
"""

from ledgerblue.comm import HIDDongleHIDAPI
import hid
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
args = parser.parse_args()

# Check the connected dongles, looking for one provisioned and sealed, one non provisioned

dongles = []
for hidDevice in hid.enumerate(0,0):
	if hidDevice['vendor_id'] == 0x2c97:
		dev = hid.device()
		dev.open_path(hidDevice['path'])
		dev.set_nonblocking(True)
		dongles.append(HIDDongleHIDAPI(dev, True, args.apdu))

if len(dongles) != 2:
	raise Exception("Expecting two dongles connected")

result1 = dongles[0].exchange("e00c000000".decode('hex'))
result2 = dongles[1].exchange("e00c000000".decode('hex'))

src = None
dest = None

if (result1[0] == 1) and (result1[1] == 1):
	src = dongles[0]
if result1[0] == 0:
	dest = dongles[0]
if (result2[0] == 1) and (result2[1] == 1):
	src = dongles[1]
if result2[0] == 0:
	dest = dongles[1]

if src == None:
	raise Exception("Source dongle not found")
if dest == None:
	raise Exception("Destination dongle not found")

# Retrieve the attestation for both applications
 
attestationSrc = src.exchange("e004000000".decode('hex'))
attestationDest = dest.exchange("e004000000".decode('hex'))

# Perform stage 1 of the export / import process : generate code bound ephemeral keys

export1 = src.exchange("e006010000".decode('hex'))
import1 = dest.exchange("e008010000".decode('hex'))

# Perform stage 2 of the export / import process : check mutual attestations

apdu = bytearray([0xe0, 0x06, 0x02, 0x00]) + bytearray([len(attestationDest)]) + attestationDest
src.exchange(apdu)
apdu = bytearray([0xe0, 0x08, 0x02, 0x00]) + bytearray([len(attestationSrc)]) + attestationSrc
dest.exchange(apdu)

# Perform stage 3 of the export / import process : check mutual ephemeral keys, generate the session key

apdu = bytearray([0xe0, 0x06, 0x03, 0x00]) + bytearray([len(import1)]) + import1
wrappedKey = src.exchange(apdu)
apdu = bytearray([0xe0, 0x08, 0x03, 0x00]) + bytearray([len(export1)]) + export1
dest.exchange(apdu)

# Import the wrapped key

apdu = bytearray([0xe0, 0x08, 0x04, 0x00]) + bytearray([len(wrappedKey)]) + wrappedKey
dest.exchange(apdu)

