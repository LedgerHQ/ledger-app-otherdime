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

from ledgerblue.comm import getDongle
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
args = parser.parse_args()

dongle = getDongle(args.apdu)
status = dongle.exchange("e00c000000".decode('hex'))
if status[0] == 0x00:
	print "Key not available"
else:
	if status[1] == 0x00:
		print "Key available, unsealed"
	else:
		print "Key available, sealed"

