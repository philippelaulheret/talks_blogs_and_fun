import binascii 
import struct
import lief



from capstone import *
from keystone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)

ks =  Ks(KS_ARCH_X86, KS_MODE_64)

def get_offset_from_ea(ea):
	return ea - 0x00000018003CEDE + 0x3c2de
	
	
	
def is_conditional_jump(mnem):

	
	test = mnem in ["jz", "jnz", "jb", "jnb", "js", "jns", "jg", "jge", "jbe", "jse", "jl", "jle", "jls", "je", "jne", "ja", "jae"]
	if not test:
		if mnem[0] == "j":
			print(mnem)
			raise
	return test



def parse_branch(data, ea, visited_ea = [], functions_to_visit = []):

	
	if ea in visited_ea:
		# We've looped back on already explored code, return immediately
		return [""]
	
	
	bVerboseLabel = True # add loc_xxx at each basic block. This is useful as a stop-gap measure to avoid having to insert labels after the fact if a bb is the target of a jmp/cal

	if bVerboseLabel:
		explored_branches = [""]
	else:
		explored_branches = ["loc_{:08x}:\n".format(ea)]
	
	while True:
		if bVerboseLabel:
			explored_branches[0] += "loc_{:08x}:\n".format(ea) # Add location tag on every bb
		
		visited_ea.append(ea)
		ran_out_of_data = True # will check  at the end of the for loop if we tried all the instruction, which would mean we need more
		offset = get_offset_from_ea(ea)
		for i in md.disasm(data[offset:offset+0x100], ea):
			#print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
			
			if i.mnemonic == "call":
				
				try:
					call_ea =  int(i.op_str, 16)
					functions_to_visit.append(call_ea)
				except:
					# will get here if we have a call rax
					pass
		
			if i.mnemonic == "jmp":
				try:
					next_ea = int(i.op_str, 16)
				except:
					# we have a jump register
					explored_branches[0] += "\tjmp {}\n".format(i.op_str)
					return explored_branches
				if next_ea in visited_ea:
					explored_branches[0] += "\tjmp loc_{:08x}\n".format(next_ea)
					return explored_branches
				else:
					ran_out_of_data = False
					ea = next_ea
					break # exit the instruction parsing loop
			elif is_conditional_jump(i.mnemonic):
				cond_address =  int(i.op_str, 16)
				if cond_address not in visited_ea:
					new_branches = parse_branch(data, cond_address, visited_ea, functions_to_visit)
					#explored_branches[0] += "\t{} loc_{:08x}\n".format(i.mnemonic, ea)
					for b in new_branches:
						explored_branches.append(b)
					
				explored_branches[0] += "\t{} loc_{:08x}\n".format(i.mnemonic, cond_address)
			else:
				explored_branches[0] += "\t%s\t%s\n" %(i.mnemonic, i.op_str)
				
				if "ret" in i.mnemonic:
					return explored_branches
				 
		
		# end instruction loop	
		if	ran_out_of_data:
			raise "RAN out of data, fix teh code"
		
		ea = next_ea
			
			
	return explored_branches
	
	
def assemble_function(branches, target_address):
	asm = ""
	for b in branches:
		asm += b
	
	print(asm)
	expected_instruction_count = len(asm.split("\n")) -1 # yolo!
	try:		
		encoding, count = ks.asm(asm, target_address)
	except KsError  as e:
		print("Failed")
		print(e)
		print("Count: %i"%e.stat_count)
		#print(statements[e.stat_count])
		count = e.stat_count
		print(asm.split("\n")[count-1])
	
	print("Encoded instruction count: {}. Expected: {}".format(count, expected_instruction_count))
	
	return encoding
	
	
def patch(data, offset, new_data):
	return data[:offset] + new_data + data[offset+len(new_data):]
	
def patch_section(filename, data, target_address):
	import lief
	print(data)
	print(hex(target_address))

	binary = lief.parse(filename)
	
	text_section = binary.get_section(".text")
	
	#print(hex(text_section.virtual_address )) # va doesn't count image base so it's like 0x1000


	#section = lief.PE.Section()
	section = lief.PE.Section(".text.deobf")
	section.virtual_address = target_address - binary.imagebase 
	#section.size = len(data) + 0x1000
	#section.characteristics = text_section.characteristics
	section.content = data
	#section.name = ".textdebof"
	#binary.add_section(section, base=target_address)
	binary.add_section(section, lief.PE.SECTION_TYPES.TEXT)

	new_filename = filename+ "_patched.bin"
	binary.write(new_filename)
	
	return new_filename
	
	
def visit_function_all(data, functions_to_visit, target_address):
	visited_functions = []
	
	
	assembled_data = [] # array of ints
	func_locations = []  # (func_address_orig, func_address_new)
	
	while len(functions_to_visit) > 0:
		f_ea = functions_to_visit.pop()
		if f_ea in visited_functions:
			continue
		# should add a test if f_ea not in .text (e.g. call imported functino)
		else:
			print("Visiting: 0x{:08x}".format(f_ea))
			visited_functions.append(f_ea)
			func_address_orig = f_ea
			func_address_new = target_address + len(assembled_data)
			
			branches = parse_branch(data, func_address_orig, functions_to_visit = functions_to_visit)
			assembled_data += assemble_function(branches, func_address_new)
			func_locations.append((func_address_orig, func_address_new))
	
	return assembled_data, func_locations
		
		
def get_entrypoint(filename):
	return lief.parse(filename).entrypoint	
			
if __name__ == "__main__":

	filename = "y0da.exe.bin"
	with open(filename, "rb") as f:
		data = f.read()
		
	target_address = 	0x18f000000
	
	if False:
		patched_data = b""
		
		func_address_orig = 0x00000018003CEDE  # function we want to patch
		func_address_new  = target_address + len(patched_data)  # where in memory the function will be at
		
		branches = parse_branch(data, func_address_orig)
		assembled_data = assemble_function(branches, func_address_new)
		func_prolog_to_patch = [(func_address_orig, func_address_new)] 
		
		
	entrypoint = get_entrypoint(filename)
	functions_to_visit = [entrypoint, 0x000018004928C, 0x18004E0E7]
	assembled_data, func_locations = visit_function_all(data, functions_to_visit, target_address)
	new_file = patch_section(filename, assembled_data, target_address)
#list of orig_ea, new_ea
	

	
	# Patch rebased binary's orig functions to jump to our deobfuscated function
	with open(new_file, "rb") as f:
		data = f.read()
	
	for (func_address_orig, func_address_new) in func_locations:
		trampoline, _ = ks.asm("jmp {}".format(func_address_new), func_address_orig) # returns a list of int
		trampoline = struct.pack("B"*len(trampoline), *trampoline)
		print(trampoline)
		
		data = patch(data, get_offset_from_ea(func_address_orig), trampoline)
	with open(new_file, "wb") as f:
		f.write(data)
		
	print("Function deobfuscated:")
	for (func_address_orig, func_address_new) in func_locations:
		print("{:08x} --> {:08x}".format(func_address_orig, func_address_new))
		

# Run the script down below in IDA to patch out the stack fixup 
# after the calls to the function that mess with the stack pointer
# We just nop out the add rsp,0x28 as they get in the way
# of the stack analysis.	
# Really we should just say that the function has a side effect on the stack
# But I couldn't get IDA to do it right :( 	
"""
auto fuck_func = 0x0180014D24;
auto cur = get_first_cref_to(fuck_func);

auto start_ea = 0x018f000000;

while (cur != BADADDR){
    auto next_ea = get_next_cref_to(fuck_func, cur);
    
    if (cur > start_ea)
    {   auto ea = next_head(cur, BADADDR);
        auto i;
        for (i=0; i < 4; i++)
        { 
            //print(i);
            patch_byte(ea +i, 0x90);
        }
    }
    cur = next_ea;
}"""

	

	


