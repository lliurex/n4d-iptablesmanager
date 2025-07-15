import os
import subprocess
import n4d.server.core


class IptablesManager:
	
	def __init__(self):
		
		os.system("modprobe ipt_owner")
		
		self.iptables_tc_skel="iptables -%s OUTPUT -o %s -m owner --uid-owner %s -m comment --comment N4D_IPTABLES_TC -j DROP"
		self.iptables_fc_skel="iptables -%s FORWARD -s %s  -p tcp ! -d 10.0.0.0/8 -m comment --comment N4D_IPTABLES_FC -j DROP"
		self.iptables_nf_skel1="iptables -%s OUTPUT -p tcp -m multiport --dports 88,389,9779 -m owner --uid-owner %s -m comment --comment N4D_IPTABLES_NF -j ACCEPT"
		self.iptables_nf_skel2="iptables -%s OUTPUT -m owner --uid-owner %s -m comment --comment N4D_IPTABLES_NF --j REJECT"
		
		
		self.blocked_list={}
		
		self.core=n4d.server.core.Core.get_core()
		
	#def init
	
	
	def block(self,user,ip=None):

		self.get_iptables_list()

		if ip=="127.0.0.1":
			#thin
			if user not in self.blocked_list:
			
				#eth=objects["VariablesManager"].get_variable("EXTERNAL_INTERFACE")
				ret=self.core.get_variable("EXTERNAL_INTERFACE")
				if ret["status"]!=0:
					return 1
				eth=ret["return"]
				cmd=self.iptables_tc_skel%("I",eth,user)
				os.system(cmd)
			
			return n4d.responses.build_successful_call_response(0)
			
		#fat
		if ip != None and ip not in self.blocked_list:
			cmd=self.iptables_fc_skel%("I",ip)
			os.system(cmd)
			return n4d.responses.build_successful_call_response(0)
			
		#nf
		if ip==None:
			if user not in self.blocked_list:
				cmd=self.iptables_nf_skel2%("I",user)
				os.system(cmd)
				cmd=self.iptables_nf_skel1%("I",user)
				os.system(cmd)
				return n4d.responses.build_successful_call_response(0)
		
		return n4d.responses.build_successful_call_response(1)
		
		
	#def block_user
	
	def unblock(self,user,ip=None):
		
		self.get_iptables_list()
		
		if ip=="127.0.0.1":
			#thin
			if user in self.blocked_list:
			
				ret=self.core.get_variable("EXTERNAL_INTERFACE")
				if ret["status"]!=0:
					return 1
				eth=ret["return"]
				cmd=self.iptables_tc_skel%("D",eth,user)
				os.system(cmd)
				
			return n4d.responses.build_successful_call_response(0)
		
		#fat
		if ip != None and ip in self.blocked_list:
		
			cmd=self.iptables_fc_skel%("D",ip)
			os.system(cmd)
			return n4d.responses.build_successful_call_response(0)
			
		#nf
		if ip==None:
			if user in self.blocked_list:
				cmd=self.iptables_nf_skel1%("D",user)
				os.system(cmd)
				cmd=self.iptables_nf_skel2%("D",user)
				os.system(cmd)
				return n4d.responses.build_successful_call_response(0)
			

		return n4d.responses.build_successful_call_response(1)
		
	#def unblock_user
	
	def is_blocked(self,item):
		
		ret=False
		
		if item in self.blocked_list:
			ret=True
			
		return n4d.responses.build_successful_call_response(ret)
		
	#def is_user_blocked
	
	
	def blocked_list(self):
		
		self.get_iptables_list()
		return n4d.responses.build_successful_call_response(self.blocked_list())
		
	#def blocked_list
	
	def get_iptables_list(self):
		
		self.blocked_list={}
		output=subprocess.Popen(["iptables -L | grep N4D_IPTABLES_"],stdout=subprocess.PIPE,shell=True).communicate()[0].decode("utf-8")
		for line in output.split("\n"):
			if len(line)>1:
				
				if "_IPTABLES_NF" in line:
					line=line.split(" ")
					#print(line)
					#0 5 7 9 22 37 41 42:
					target,prot,opt,source,destination,ports,user,comment=line[0],line[5],line[7],line[9],line[22],line[37],line[41]," ".join(line[42:])
						
					
					info={}
					info["target"]=target
					info["prot"]=prot
					info["opt"]=opt
					info["source"]=source
					info["destination"]=destination
					info["comment"]=comment
					info["user"]=user
					info["client_type"]="N4D_IPTABLES_NF"
					self.blocked_list[user]=info				
				
				
				else:
					line=line.split(" ")
					#0 7 9 11 24 37:
					target,prot,opt,source,destination,comment=line[0],line[7],line[9],line[11],line[21]," ".join(line[37:])
					try:
						user,client_type=line[40],line[42]
						ip="127.0.0.1"
					except:
						user=source
						ip=source
						client_type="N4D_IPTABLES_FC"
						
					
					info={}
					info["target"]=target
					info["prot"]=prot
					info["opt"]=opt
					info["source"]=source
					info["destination"]=destination
					info["comment"]=comment
					info["user"]=user
					info["client_type"]=client_type
					info["ip"]=ip
					self.blocked_list[user]=info
				
					
				
		#print(self.blocked_list)
				

	#def iptables_list
	

#class IptablesManager


if __name__=="__main__":
	
	im=IptablesManager()
	'''
	im.get_iptables_list()
	for item in im.blocked_list:
		print("[%s]"%item)
		for item2 in im.blocked_list[item]:
			print("\t[%s] = %s "%(item2,im.blocked_list[item][item2]))
	'''
	ret=im.block("lliurex")
	print(ret)
	ret=im.unblock("lliurex")
	print(ret)
		
		
		
		