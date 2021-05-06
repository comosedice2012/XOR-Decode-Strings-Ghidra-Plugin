#Deobfuscate string variables in Ghidra and print as comment
#Ryan Blevins


#-------------------------------------------------------------------------------------------
def get_string(addr, size):
	"""Get strings one byte at a time"""
	
	output = ''
	for offset in range(size):
		output += chr(getByte(addr))
		addr = addr.add(1)

	return output


#-------------------------------------------------------------------------------------------
def decode(encoded_key, encoded_string, size):
	"""Use XOR to decode string with key"""
	
	decoded_string = ''
	i = 0
	for i in range(0, size):
		decoded_string = decoded_string + chr(ord(encoded_string[i]) ^ ord(encoded_key[i % len(encoded_key)]))
	
	return str(decoded_string)


#-------------------------------------------------------------------------------------------
def main():
	"""Main"""

	print '[*] Deobfuscating strings...'

	for x in getReferencesTo(toAddr("FUN_10001210")):

		#get address of obfuscated string
		ref_addr = x.getFromAddress().toString()
		prev_instr = getInstructionBefore(toAddr(ref_addr))
		instr_addr = prev_instr.getAddress()
		enc_addr = toAddr(prev_instr.getOpObjects(0)[0].toString())
	
		#get address of 'key' string
		prev_instr = getInstructionBefore(toAddr(instr_addr.toString()))
		instr_addr = prev_instr.getAddress()
		key_addr = toAddr(prev_instr.getDefaultOperandRepresentation(0))
	
		#get string size in int
		prev_instr = getInstructionBefore(toAddr(instr_addr.toString()))
		hex_size = prev_instr.getDefaultOperandRepresentation(0)
		int_size = int(hex_size, 16)

		#get key/string
		encoded_key = get_string(key_addr, int_size)
		encoded_string = get_string(enc_addr, int_size)
		
		decoded_string = decode(encoded_key, encoded_string, int_size)

		#write deobfuscated string in comments
		comment_addr = (getInstructionAfter(getInstructionAfter(x.getFromAddress()))).getAddress()
		listing = currentProgram.getListing()
		codeUnit = listing.getCodeUnitAt(comment_addr)
		codeUnit.setComment(codeUnit.EOL_COMMENT, '[*] ' + decoded_string)

		print '[*] Address 0x' + comment_addr.toString() + ':  ' + decoded_string

	print '[*] Done.'


if __name__ == '__main__':
	main()
