#-*- coding: utf-8 -*-
import random
import datetime
import tkinter as tk

class SimpleDES:
	def __init__(self,key):
		#암호화 func
		self.IP = [2,6,3,1,4,8,5,7]
		self.EP = [4,1,2,3,2,3,4,1]
		self.S0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
		self.S1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
		self.P4 = [2,4,3,1]

		#key생성
		self.P10 = [3,5,2,7,4,10,1,9,8,6]
		self.P8 = [6,3,7,4,8,5,10,9]
		self.key = (int(key,2)) #10bit key값 설정

	def keygen(self):
		k = "{0:b}".format(self.key).zfill(10) #이진수 문자열로 변경

		key = []
		for i in range(0,10): # P10박스 
			key.append(k[self.P10[i]-1])

		tmp = key[0] # left shift
		for i in range(0,4):
			key[i] = key[i+1]
		key[4] = tmp

		tmp = key[5] # left shift
		for i in range(5,9):
			key[i] = key[i+1]
		key[9] = tmp

		k1 = []
		for i in range(0,8): # P8박스
			k1.append(key[self.P8[i]-1])
		key1 = "".join(k1) # key1생성		

		for x in range(0,2): # left shift 2번
			tmp = key[0] # left shift
			for i in range(0,4):
				key[i] = key[i+1]
			key[4] = tmp
	  
			tmp = key[5] # left shift
			for i in range(5,9):
				key[i] = key[i+1]
			key[9] = tmp

		k2 = []
		for i in range(0,8): # P8박스
			k2.append(key[self.P8[i]-1])
		key2 = "".join(k2) # key2생성
		
		return key1,key2

	def func(self, left, right, key):

		#right = t_list[4:8]
		right_ep = []
		for i in range(0,8): 
			right_ep.append(right[self.EP[i]-1]) # E/P확장

		s = "{0:b}".format(int("".join(right_ep),2)^int(key,2)).zfill(8) #1번째 xor

		s_l = s[0]+s[3] #S0
		s_r = s[1]+s[2]
		ss = "{0:b}".format(self.S0[int(s_l,2)][int(s_r,2)]).zfill(2)

		s_l = s[4]+s[7] #S1
		s_r = s[5]+s[6]
		ss = ss+"{0:b}".format(self.S1[int(s_l,2)][int(s_r,2)]).zfill(2)

		p4 = []
		for i in range(0,4):	# P4
			p4.append(ss[self.P4[i]-1])

		s = int(left,2)^int("".join(p4),2) #2번째 xor

		return "{0:b}".format(s).zfill(4)

	def crypt(self,plain):
		t_list = []
		for i in range(0,8): # IP
			t_list.append(plain[self.IP[i]-1])

		left = self.func("".join(t_list[0:4]),"".join(t_list[4:8]),self.keygen()[0])
		right = "".join(t_list[4:8]) #1라운드

		left2 = self.func(right,left,self.keygen()[1]) #swap and 2라운드
		right2 = left

		full = left2+right2

		i_IP = self.inverse_order_IP()
		final = []
		for i in range(0,8): # inverse_IP
			final.append(full[i_IP[i]-1])

		return "".join(final)

	def decrypt(self,crypt):
		t_list = []
		i_IP = self.inverse_order_IP()
		for i in range(0,8): # inverse_IP
			t_list.append(crypt[self.IP[i]-1])

		left = self.func("".join(t_list[0:4]),"".join(t_list[4:8]),self.keygen()[1])
		right = "".join(t_list[4:8]) #1라운드

		left2 = self.func(right,left,self.keygen()[0]) #swap and 2라운드
		right2 = left

		full = left2+right2

		final = []
		for i in range(0,8): # IP
			final.append(full[i_IP[i]-1])

		return "".join(final)

	def inverse_order_IP(self):
		inverse_IP = [0,0,0,0,0,0,0,0]
		for i in range(0,8):
			inverse_IP[self.IP[i]-1] = i+1
		return inverse_IP

class ECB: 
	def crypt(self,plain,key):
		crypt = ""
		des = SimpleDES(key)
		for i in range(0,len(plain)):
			crypt += chr(int(des.crypt("{0:b}".format(ord(plain[i])).zfill(8)),2))
		return crypt

	def decrypt(self,crypt,key):
		plain = ""
		des = SimpleDES(key)
		for i in range(0,len(crypt)):
			plain += chr(int(des.decrypt("{0:b}".format(ord(crypt[i])).zfill(8)),2))
		return plain

class CBC:
	def __init__(self,iv):
		self.iv = iv
	def crypt(self,plain,key):
		crypt = ""
		p=""
		des = SimpleDES(key)
		for i in range(0,len(plain)):
			if i==0: 
				p += chr(self.iv^ord(plain[i]))
			else:
				p += chr(ord(crypt[i-1])^ord(plain[i]))
			crypt += chr(int(des.crypt("{0:b}".format(ord(p[i])).zfill(8)),2))
		return crypt

	def decrypt(self,crypt,key):
		plain = ""
		c=""
		des = SimpleDES(key)
		for i in range(0,len(crypt)):
			c += chr(int(des.decrypt("{0:b}".format(ord(crypt[i])).zfill(8)),2))
			if i==0:
				plain += chr(self.iv^ord(c[i]))
			else:
				plain += chr(ord(crypt[i-1])^ord(c[i]))
			
		return plain

class CFB:
	def __init__(self,iv):
		self.iv = iv
	def crypt(self,plain,key):
		crypt = ""
		des = SimpleDES(key)
		for i in range(0,len(plain)):
			if i==0:
				crypt += chr(ord(plain[i])^ord(chr(int(des.crypt("{0:b}".format(self.iv).zfill(8)),2))))
			else:
				crypt += chr(ord(plain[i])^(int(des.crypt("{0:b}".format(ord(crypt[i-1])).zfill(8)),2)))
		return crypt

	def decrypt(self,crypt,key):
		plain = ""
		des = SimpleDES(key)
		for i in range(0,len(crypt)):
			if i==0:
				plain += chr(ord(crypt[i])^(int(des.crypt("{0:b}".format(self.iv).zfill(8)),2)))
			else:
				plain += chr(ord(crypt[i])^int(des.crypt("{0:b}".format(ord(crypt[i-1])).zfill(8)),2))
		return plain

class OFB:
	def __init__(self,iv):
		self.iv = iv
	def crypt(self,plain,key):
		crypt = ""
		iv_ofb = 0
		des = SimpleDES(key)
		for i in range(0,len(plain)):
			if i==0:
				iv_ofb = int(des.crypt("{0:b}".format(self.iv).zfill(8)),2)
				crypt += chr(ord(plain[i])^iv_ofb)
			else:
				iv_ofb = int(des.crypt("{0:b}".format(iv_ofb).zfill(8)),2)
				crypt += chr(ord(plain[i])^iv_ofb)
		return crypt

class CTR:
	def __init__(self,nonce):
		tmp = "{0:b}".format(nonce).zfill(4)
		for i in range(0,4):		
			tmp += "0"
		self.ctr = int(tmp,2) + 1 #1번째 블록
	def crypt(self,plain,key):
		crypt = ""
		ctr = self.ctr
		des = SimpleDES(key)
		for i in range(0,len(plain)):
			crypt += chr(ord(plain[i])^int(des.crypt("{0:b}".format(ctr).zfill(8)),2))
			ctr+=1
			
		return crypt

class Gui:
	def __init__(self):
		root = tk.Tk()
		frame = tk.Frame(root, width = 400, height = 800)
		frame.pack()

		help = tk.Label(frame,text="가이드라인\n 1.복호화나 hack할 시 초기화 벡터를 넣어주세요.\n2.hack할 경우 블록모드 다중 선택이 가능합니다.\n3.hack의 경우 시간이 오래 걸릴수 있으니 주의해주세요.\n4.초기화 벡터 입력안할시 자동으로 난수를 생성합니다.\n5.CTR모드의 경우 앞의 4bit는 nonce,뒤의 4bit는 블록번호\n6.암호문의 경우 ascii비트를 초과하는 경우 출력 불가능 합니다.")
		help.grid(column=0, row=0)

		f0 = tk.Frame(frame, background="#B7F0B1",height = 100, width = 380)
		f0.grid(column = 0, row = 1)

		##### f0 프레임 #####
		mod = tk.Label(f0,text="블록모드")
		mod.grid(column=0,row=0)

		self.ecb = tk.IntVar()
		ecb_check = tk.Checkbutton(f0, text="ECB",variable = self.ecb)
		self.cbc = tk.IntVar()
		cbc_check = tk.Checkbutton(f0, text="CBC",variable = self.cbc)
		self.cfb = tk.IntVar()
		cfb_check = tk.Checkbutton(f0, text="CFB",variable = self.cfb)
		self.ofb = tk.IntVar()
		ofb_check = tk.Checkbutton(f0, text="OFB",variable = self.ofb)
		self.ctr = tk.IntVar()
		ctr_check = tk.Checkbutton(f0, text="CTR",variable = self.ctr)
		
		ecb_check.grid(row = 0, column=1)
		cbc_check.grid(row = 0, column=2)
		cfb_check.grid(row = 0, column=3)
		ofb_check.grid(row = 0, column=4)
		ctr_check.grid(row = 0, column=5)
		##### f0 프레임 ######

		##### f2 프레임 ######
		f2 = tk.Frame(frame,height = 100, width = 380)
		f2.grid(column = 0, row = 2)

		l3 = tk.Label(f2,text="IV")
		l3.grid(column=0,row=0)
		self.iv = tk.Entry(f2)
		self.iv.grid(row = 0, column=1)

		l4 = tk.Label(f2,text="KEY")
		l4.grid(column=0,row=1)
		self.key = tk.Entry(f2)
		self.key.grid(row = 1, column=1)
		##### f2 프레임 ######

		##### f1 프레임 ######
		f1 = tk.Frame(frame,height = 100, width = 380)
		f1.grid(column = 0, row = 3)

		l1 = tk.Label(f1,text="평문")
		l1.grid(column=0,row=0)
		self.plain = tk.Entry(f1)
		self.plain.grid(row = 0, column=1)
		crypt = tk.Button(f1, text="암호화", command = self.crypt_plain)
		crypt.grid(row = 0, column=2)

		l2 = tk.Label(f1,text="암호문")
		l2.grid(column=0,row=1)
		self.cipher = tk.Entry(f1)
		self.cipher.grid(row = 1, column=1)
		crypt = tk.Button(f1, text="복호화", command = self.decrypt_cipher)
		crypt.grid(row = 1, column=2)
		##### f1 프레임 ######

		##### f4 프레임 ######
		f4 = tk.Frame(frame,height = 100, width = 380)
		f4.grid(column = 0, row = 4)

		l6 = tk.Label(f4,text="!!hack!! 부하에 주의하세요.")
		l6.grid(column=0,row=0)
		hack = tk.Button(f4, text="HACK", command = self.brute_force)
		hack.grid(row = 0, column=1)
		##### f4 프레임 ######

		f3 = tk.Frame(frame,width=380, height=80,bg = '#ffffff',
				  borderwidth=1, relief="sunken")
		scrollbar = tk.Scrollbar(f3) 
		self.editArea = tk.Text(f3, width=50, height=10, wrap="word",
				   yscrollcommand=scrollbar.set,
				   borderwidth=0, highlightthickness=0)
		scrollbar.config(command=self.editArea.yview)
		scrollbar.pack(side="right", fill="y")
		self.editArea.pack(side="left", fill="both", expand=True)
		f3.grid(row = 5, column = 0)

		root.mainloop()
	def crypt_plain(self):
		if(self.plain.get() == "" or self.error_check() != ""):
			self.editArea.delete('1.0',tk.END)
			self.editArea.insert(tk.END,"평문을 입력하세요.")
			self.editArea.insert(tk.END,(self.error_check()))
		elif(self.key_check() == 0):
			self.editArea.delete('1.0',tk.END)
			self.editArea.insert(tk.END,"올바른 키값을 입력하시오.\n")
			self.editArea.insert(tk.END,"key는 10bit가 되어야 합니다.\n")
			self.editArea.insert(tk.END,"이진수로 입력해 주세요.\n")
	
		else :
			if(self.ecb.get()):
				start = datetime.datetime.now()
				c_ecb = ECB()
				self.cipher.delete(0,tk.END)
				self.cipher.insert(0,c_ecb.crypt(self.plain.get(),self.key.get()))
				self.bit_print(0)
				end = datetime.datetime.now()
				diff = end - start
				elapsed_ms = (diff.microseconds)
				self.editArea.insert(tk.END,"걸린시간 : "+str(elapsed_ms)+" microseconds\n")
			elif(self.iv_check() == 0):
				self.editArea.delete('1.0',tk.END)
				self.editArea.insert(tk.END,"올바른 iv값을 입력하시오.\n")
				self.editArea.insert(tk.END,"1과0 8자리만 올 수 있습니다.")
			else:
				start = datetime.datetime.now()
				if(self.iv.get() == ""):
					self.iv.insert(tk.END,"{0:b}".format(random.randint(1,255)).zfill(8))
			
				if(self.cbc.get()):
					c_cbc = CBC(int(self.iv.get(),2))
					self.cipher.delete(0,tk.END)
					self.cipher.insert(0,c_cbc.crypt(self.plain.get(),self.key.get()))
				elif(self.cfb.get()):
					c_cfc = CFB(int(self.iv.get(),2))
					self.cipher.delete(0,tk.END)
					self.cipher.insert(0,c_cfc.crypt(self.plain.get(),self.key.get()))
				elif(self.ofb.get()):
					c_ofb = OFB(int(self.iv.get(),2))
					self.cipher.delete(0,tk.END)
					self.cipher.insert(0,c_ofb.crypt(self.plain.get(),self.key.get()))
				elif(self.ctr.get()):
					iv_ = self.iv.get()[0:4]
					for i in range(0,4):
						iv_ += "0"
					self.iv.delete(0,tk.END)
					self.iv.insert(0,iv_)
					c_ctr = CTR(int(self.iv.get()[0:4],2))
					self.cipher.delete(0,tk.END)
					self.cipher.insert(0,c_ctr.crypt(self.plain.get(),self.key.get()))
				self.bit_print(0)
				end = datetime.datetime.now()
				diff = end - start
				elapsed_ms = (diff.microseconds)
				self.editArea.insert(tk.END,"걸린시간 : "+str(elapsed_ms)+"microseconds\n")

	def decrypt_cipher(self):
		if(self.key_check() == 0):
			self.editArea.delete('1.0',tk.END)
			self.editArea.insert(tk.END,"올바른 키값을 입력하시오.\n")
			self.editArea.insert(tk.END,"key는 10bit가 되어야 합니다.\n")
			self.editArea.insert(tk.END,"이진수로 입력해 주세요.\n")

		elif(self.cipher.get() == "" or self.error_check() != ""):
			self.editArea.delete('1.0',tk.END)
			self.editArea.insert(tk.END,"암호문을 입력하세요.")
			self.editArea.insert(tk.END,(self.error_check()))
	
		else :
			if(self.ecb.get()):
				start = datetime.datetime.now()
				c_ecb = ECB()
				self.plain.delete(0,tk.END)
				self.plain.insert(0,c_ecb.decrypt(self.cipher.get(),self.key.get()))
				self.bit_print(1)
				end = datetime.datetime.now()
				diff = end - start
				elapsed_ms = (diff.microseconds)
				self.editArea.insert(tk.END,"걸린시간 : "+str(elapsed_ms)+"microseconds\n")
			elif(self.iv_check() == 0):
				self.editArea.delete('1.0',tk.END)
				self.editArea.insert(tk.END,"올바른 iv값을 입력하시오.\n")
				self.editArea.insert(tk.END,"1과0 8자리만 올 수 있습니다.")

			else:
				start = datetime.datetime.now()
				if(self.iv.get() == ""):
					self.iv.insert(tk.END,"{0:b}".format(random.randint(1,255)).zfill(8))
			
				if(self.cbc.get()):
					c_cbc = CBC(int(self.iv.get(),2))
					self.plain.delete(0,tk.END)
					self.plain.insert(0,c_cbc.decrypt(self.cipher.get(),self.key.get()))
				elif(self.cfb.get()):
					c_cfc = CFB(int(self.iv.get(),2))
					self.plain.delete(0,tk.END)
					self.plain.insert(0,c_cfc.decrypt(self.cipher.get(),self.key.get()))
				elif(self.ofb.get()):
					c_ofb = OFB(int(self.iv.get(),2))
					self.plain.delete(0,tk.END)
					self.plain.insert(0,c_ofb.crypt(self.cipher.get(),self.key.get()))
				elif(self.ctr.get()):
					iv_ = self.iv.get()[0:4]
					for i in range(0,4):
						iv_ += "0"
					self.iv.delete(0,tk.END)
					self.iv.insert(0,iv_)
					c_ctr = CTR(int(self.iv.get()[0:4],2))
					self.plain.delete(0,tk.END)
					self.plain.insert(0,c_ctr.crypt(self.cipher.get(),self.key.get()))
				self.bit_print(1)
				end = datetime.datetime.now()
				diff = end - start
				elapsed_ms = (diff.microseconds)
				self.editArea.insert(tk.END,"걸린시간 : "+str(elapsed_ms)+"microseconds\n")

	def key_check(self):
		if(len(self.key.get()) != 10):
			return 0
		else:
			for i in range(0,8):
				if(self.key.get()[i] != "1" and self.key.get()[i] != "0"):
					return 0
		return 1
	def bit_print(self, cord):
		self.editArea.delete('1.0',tk.END)
		if(cord == 0):
			for i in range(0,len(self.cipher.get())):
				self.editArea.insert(tk.END,str(i)+"번째 블록비트 : "+"{0:b}".format(ord(self.plain.get()[i])).zfill(8)+" ---> "+"{0:b}".format(ord(self.cipher.get()[i])).zfill(8)+"\n")
		elif(cord == 1):
			for i in range(0,len(self.plain.get())):
				self.editArea.insert(tk.END,str(i)+"번째 블록비트 : "+"{0:b}".format(ord(self.cipher.get()[i])).zfill(8)+" ---> "+"{0:b}".format(ord(self.plain.get()[i])).zfill(8)+"\n")

	def error_check(self):
		c = self.ecb.get() + self.cbc.get() + self.cfb.get() + self.ofb.get() + self.ctr.get()
		if(c > 1):
			return "암복호화시 블록모드 다중 선택 불가"
		elif(c < 1):
			return "블록모드를 선택해주세요.!"
		return ""

	def iv_check(self):
		if(len(self.iv.get()) == 0):
			return 1
		if(len(self.iv.get()) != 8):
			return 0
		else:
			for i in range(0,8):
				if(self.iv.get()[i] != "1" and self.iv.get()[i] != "0"):
					return 0
		return 1
	
	def brute_force(self):
		hack = HACK()
		mode=""

		if(self.ecb.get() == 1):
			mode = "ecb"
		if(self.cbc.get() == 1):
			mode = "cbc"
		if(self.cfb.get() == 1):
			mode = "cfb"
		if(self.ofb.get() == 1):
			mode = "ofb"
		if(self.ctr.get() == 1):
			mode = "ctr"

		r = hack.hack(self.cipher.get(),mode,self.iv.get())
		self.editArea.delete('1.0',tk.END)
		self.editArea.insert(tk.END,"걸린시간 : "+str(r[0])+"microseconds\n")
		if(r[1] == -1):		
			self.editArea.insert(tk.END,"단어를 찾는데에 실패 하였습니다.\n")
		else:
			self.editArea.insert(tk.END,"key 값 : "+str(r[1])+"\n")
			self.editArea.insert(tk.END,"찾은 평문 : "+str(r[2])+"\n")
		
class HACK:
	def open_engDictionary(self):
		eng = [] 
		f = open("words.txt", 'r')
		
		while True:
		    eng.append(f.readline())
		    if not f.readline(): break

		f.close()
		
		return eng

	def check_ascii(self, crypt):
		for i in range(0, len(crypt)):
			if(ord(crypt[i]) > 128):
				return 0
		return 1

	def hack(self,crypt,mode,iv):

		check = 0

		if(mode == "ecb"):
			self.mod = ECB()
		elif(mode == "cbc"):
			self.mod = CBC(int(iv,2))
		elif(mode == "cfb"):
			self.mod = CFB(int(iv,2))
		elif(mode == "ofb"):
			check = 1
			self.mod = OFB(int(iv,2))
		elif(mode == "ctr"):
			check = 1
			self.mod = CTR(int(iv[0:4],2))

		key = -1
		plain = ""

		print("영어사전을 오픈합니다....\n")
		eng = self.open_engDictionary()

		print("hack을 시작합니다.\n")
		start = datetime.datetime.now()
		#key의 범위는 2^10 0~1024 대입
		
		for k in range(0,1024):
			if(check == 0):
				plain = self.mod.decrypt(crypt,"{0:b}".format(k).zfill(10))
			elif(check == 1):
				plain = self.mod.crypt(crypt,"{0:b}".format(k).zfill(10))
		
			if(self.check_ascii(plain) != 0):	
				if(self.compare_word(plain,eng) == 1):
					key = k 
					break				

		end = datetime.datetime.now()
		diff = end - start
		elapsed_ms = (diff.microseconds)

		result = []

		result.append(elapsed_ms)
		result.append("{0:b}".format(key).zfill(8))
		result.append(plain)

		return result
		

	def compare_word(self,word,eng):
		for i in range(0,len(eng)):
			if( (word+"\n") == eng[i]):
				return 1
		return 0
		
if __name__ == "__main__":
	gui = Gui()


