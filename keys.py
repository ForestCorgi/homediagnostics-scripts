import idautils
import idc
import os

from flare import jayutils, argtracker

def parse_xrefs(xrefs):
	rsas = set()
	
	for xref in xrefs:
		name = None
		rsa = None
		
		ea = xref
		
		for i in range(0, 7):
			decoded_instruction = idautils.DecodePreviousInstruction(ea)
			xrefs_from = idautils.XrefsFrom(decoded_instruction.ea)
			
			for ref in xrefs_from:
				if ref.type == 1:
					s = idc.GetString(ref.to)
					
					if s:
						rsa = s
				elif ref.type == 21 and idc.GetDisasm(ref.to).find("cfstr") != -1:
					cfstr_xrefs = idautils.XrefsFrom(ref.to)
					
					for cfstr_xref in cfstr_xrefs:
						if cfstr_xref.type == 1:
							for cfstr_xref2 in idautils.XrefsFrom(cfstr_xref.to):
								s = idc.GetString(cfstr_xref2.to)
								if s and s.strip() != "":
									name = s
									
									if name and rsa:
										rsas.add((name, rsa))
			ea = decoded_instruction.ea
	
	return [{"name": x[0].strip(), "rsa": x[1].strip()} for x in rsas]

def save_obj(save_dir, obj):
	name = obj["name"]
	rsa = obj["rsa"]
	
	if rsa.find("PRIVATE") != -1:
		ext = "key"
		obj_type = "private key"
	elif rsa.find("PUBLIC") != -1:
		ext = "public"
		obj_type = "public key"
	elif rsa.find("CERTIFICATE") != -1:
		ext = "cert"
		obj_type = "certificate"
	else:
		print("This shouldn't happen.")
		return
	
	save_name = name
	
	if save_name.split(".")[-1] != ext:
		save_name += "." + ext
	
	print("Saving {} {}...".format(obj_type, name))
	
	with open(os.path.join(save_dir, save_name), "w") as obj_file:
		obj_file.write(rsa)

key_func = idc.LocByName("_AMAuthInstallCryptoRegisterKeysFromPEMBuffer")
cert_func = idc.LocByName("_AMAuthInstallCryptoRegisterCertFromPEMBuffer")
input_path = jayutils.getInputFilepath()
vw = jayutils.loadWorkspace(input_path, fatarch="amd64")
tracker = argtracker.ArgTracker(vw)

key_xrefs = idautils.CodeRefsTo(key_func, 1)
cert_xrefs = idautils.CodeRefsTo(cert_func, 1)

keys = parse_xrefs(key_xrefs)
certs = parse_xrefs(cert_xrefs)

save_dir = "{}-keys".format(input_path)

if not os.path.exists(save_dir):
	os.mkdir(save_dir)

for obj in (keys + certs):
	save_obj(save_dir, obj)

print("Done!")