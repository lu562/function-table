

# This file was *autogenerated* from the file LTZTable.sage
from sage.all_cmdline import *   # import sage library

_sage_const_8 = Integer(8); _sage_const_2 = Integer(2); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0)#basic param
#n = 64
k = _sage_const_8 
l = _sage_const_8 
n = k*l

#generated basic param
#p = random_prime(2^n-1, false, 2^(n-1))
p = _sage_const_2 **n
#F = Integers(p)
F = Integers(_sage_const_2 **n)
#F2 = Integers(2^n)
F2 = Integers(_sage_const_2 )
# F3 = Integers(2^n)
F3 = Integers(_sage_const_4 )


#ENUM for output
POS = Integers(_sage_const_3 )(_sage_const_1 )
NEG = Integers(_sage_const_3 )(_sage_const_2 )
UNK = Integers(_sage_const_3 )(_sage_const_0 )

#Random values
# r = F.random_element()
r = F(_sage_const_0 )
b = int(Integers(_sage_const_2 ).random_element())
#b = 0
rArr = [[]]*k
for i in range(k):
	rArr[i] = Integers(_sage_const_3 ).random_element()
	rArr[i] = Integers(_sage_const_3 )(_sage_const_0 )

#Function tables
table1 = [rArr[_sage_const_0 ]]*(_sage_const_2 **l)
bTable = [b]*(_sage_const_2 **l)
sofsoft = [ [[]]*(k-_sage_const_1 ) ,  [[]]*(k-_sage_const_1 )]
for i in range(k-_sage_const_1 ):
	sofsoft[_sage_const_0 ][i] = [rArr[i+_sage_const_1 ]]*(_sage_const_2 **l)
	sofsoft[_sage_const_1 ][i] = [rArr[i+_sage_const_1 ]]*(_sage_const_2 **l)

Unk0 = ""
Unk1 = ""
end1 = _sage_const_0 
end2 = int(p/_sage_const_2 )



#Begin filling the function tables

#first block
for i in range(_sage_const_2 **l):
	inp = "0"*(l-len(bin(i)[_sage_const_2 :])) + bin(i)[_sage_const_2 :]
	res = UNK
	minstr = inp + "0"*(n-len(inp))
	minv = int(minstr, _sage_const_2 )
	if minv >= p:
		res = (int)(Integers(_sage_const_3 ).random_element())
		res = _sage_const_0 
		table1[i] += res
		continue
	maxstr = inp + "1"*(n-len(inp))
	maxv = min(int(maxstr, _sage_const_2 ), p-_sage_const_1 )
	minr = NEG
	maxr = NEG
	minv = int(F(minv) - r)
	maxv = int(F(maxv) - r)
	
	if minv >= end1 and minv <= end2:
		minr = POS
	if maxv >= end1 and maxv <= end2:
		maxr = POS
	
	if minr == NEG and maxr == POS:
		Unk0 = inp
		res = UNK
	if minr == POS and maxr == NEG:
		Unk1 = inp
		bTable[i] = _sage_const_1 -b
		res = UNK
	
	if minr == POS and maxr == POS:
		res = POS
	if minr == NEG and maxr == NEG:
		res = NEG
	table1[i] = table1[i] + res

if Unk0 == "":
	Unk0 = Unk1
if Unk1 == "":
	Unk1 = Unk0


#all other blocks
for i in range(k-_sage_const_1 ):
	for j in range(_sage_const_2 **l):
		inp = "0"*(l-len(bin(j)[_sage_const_2 :])) + bin(j)[_sage_const_2 :]
		#Unk0
		if len(Unk0)/l < i+_sage_const_1 :
			break
		#Function to determine results
		Unk = Unk0
		res = UNK
		minstr = Unk + inp + "0"*(n-len(Unk+inp))
		minv = int(minstr, _sage_const_2 )
		if minv >= p:
			res = (int)(Integers(_sage_const_3 ).random_element())
			res = _sage_const_0 
			sofsoft[b][i][j] += res
			continue
		maxstr = Unk + inp + "1"*(n-len(Unk+inp))
		maxv = min(int(maxstr, _sage_const_2 ), p-_sage_const_1 )
		
		minv = int(F(minv) - r)
		maxv = int(F(maxv) - r)
		
		minr = NEG
		maxr = NEG
		if minv >= end1 and minv <= end2:
			minr = POS
		if maxv >= end1 and maxv <= end2:
			maxr = POS
		if minr == POS and maxr == POS:
			res = POS
		if minr == NEG and maxr == NEG:
			res = NEG
		
		if res == UNK:
			Unk0 = Unk0 + inp
		
		sofsoft[b][i][j] += res
	
	for j in range(_sage_const_2 **l):
		inp = "0"*(k-len(bin(j)[_sage_const_2 :])) + bin(j)[_sage_const_2 :]
		#Unk1
		if len(Unk1)/l < i+_sage_const_1 :
			break
		#Function to determine results
		Unk = Unk1
		res = UNK
		minstr = Unk + inp + "0"*(n-len(Unk+inp))
		minv = int(minstr, _sage_const_2 )
		if minv >= p:
			res = (int)(Integers(_sage_const_3 ).random_element())
			res = _sage_const_0 
			sofsoft[_sage_const_1 -b][i][j] += res
			continue
		maxstr = Unk + inp + "1"*(n-len(Unk+inp))
		maxv = min(int(maxstr, _sage_const_2 ), p-_sage_const_1 )
		
		minv = int(F(minv) - r)
		maxv = int(F(maxv) - r)
		
		minr = NEG
		maxr = NEG
		if minv >= end1 and minv <= end2:
			minr = POS
		if maxv >= end1 and maxv <= end2:
			maxr = POS
		if minr == POS and maxr == POS:
			res = POS
		if minr == NEG and maxr == NEG:
			res = NEG
		
		if res == UNK:
			Unk1 = Unk1 + inp
		
		sofsoft[_sage_const_1 -b][i][j] += res


recTable = [F(_sage_const_0 )]*(_sage_const_3 **k)
#UnkStr = ""
#for i in range(k):
#	UnkStr = str(UNK - rArr[i]) + UnkStr
#print(UnkStr)
for i in range(k):
	negstr = ""
	for j in range(i):
		negstr = negstr + str(UNK - rArr[j])
	negstr = negstr + str(NEG - rArr[i])
	
	for j in range(_sage_const_3 **(k-_sage_const_1 -i)):
		tailstr = "0"*(k-_sage_const_1 -i-len(Integer(j).digits(_sage_const_3 )))
		for c in range(len(Integer(j).digits(_sage_const_3 ))-_sage_const_1 , -_sage_const_1 , -_sage_const_1 ):
			tailstr = tailstr + str(Integer(j).digits(_sage_const_3 )[c])
		recTable[int(negstr + tailstr, _sage_const_3 )] = F(_sage_const_1 )

'''
for i in range(3^k):
	s = "0"*(k-len(Integer(i).digits(3)))
	for j in range(len(Integer(i).digits(3))-1, -1, -1):
		s = s + str(Integer(i).digits(3)[j])
	print(s + "\t" + str(recTable[i]))
'''

#Secret Sharing the Tables
bTable_1 = [F2(_sage_const_0 )]*(_sage_const_2 **l)
bTable_2 = [F2(_sage_const_0 )]*(_sage_const_2 **l)
for i in range(_sage_const_2 **l):
	a = int(F2.random_element())
	bTable_2[i] = a
	bTable_1[i] = F2(int(bTable[i])) - a

table1_1 = [F3(_sage_const_0 )]*(_sage_const_2 **l)
table1_2 = [F3(_sage_const_0 )]*(_sage_const_2 **l)
for i in range(_sage_const_2 **l):
	a = F3.random_element()
	table1_2[i] = a
	table1_1[i] = F3(int(table1[i])) - a

sofsoft_1 = [ [[]]*(k-_sage_const_1 ) ,  [[]]*(k-_sage_const_1 )]
sofsoft_2 = [ [[]]*(k-_sage_const_1 ) ,  [[]]*(k-_sage_const_1 )]
for i in range(k-_sage_const_1 ):
	sofsoft_1[_sage_const_0 ][i] = [F3(_sage_const_0 )]*(_sage_const_2 **l)
	sofsoft_1[_sage_const_1 ][i] = [F3(_sage_const_0 )]*(_sage_const_2 **l)
	sofsoft_2[_sage_const_0 ][i] = [F3(_sage_const_0 )]*(_sage_const_2 **l)
	sofsoft_2[_sage_const_1 ][i] = [F3(_sage_const_0 )]*(_sage_const_2 **l)
for i in range(k-_sage_const_1 ):
	for j in range(_sage_const_2 **l):
		a = F3.random_element()
		sofsoft_2[_sage_const_0 ][i][j] = a
		sofsoft_1[_sage_const_0 ][i][j] = F3(int(sofsoft[_sage_const_0 ][i][j])) - a
		a = F3.random_element()
		sofsoft_2[_sage_const_1 ][i][j] = a
		sofsoft_1[_sage_const_1 ][i][j] = F3(int(sofsoft[_sage_const_1 ][i][j])) - a

recTable_1 = [F(_sage_const_0 )]*(_sage_const_3 **k)
recTable_2 = [F(_sage_const_0 )]*(_sage_const_3 **k)
for i in range(_sage_const_3 **k):
	a = F.random_element()
	recTable_1[i] = a
	recTable_2[i] = recTable[i] - a

r_1 = F.random_element()
r_2 = r - r_1

'''
print("overall:")
print("p: " + str(p))
print("n: " + str(n))
print("POS: " + str(POS))
print("NEG: " + str(NEG))
print("UNK: " + str(UNK))
print("b: " + str(b))
print("r: " + str(r))
print("rArr: " + str(rArr))
print("bTable: " + str(bTable))
print("table1: " + str(table1))
print("sofsoft: " + str(sofsoft))
print("recTable: " + str(recTable))

print("\n\n\n")

	
print("party 1:")
print("p: " + str(p))
print("n: " + str(n))
print("POS: " + str(POS))
print("NEG: " + str(NEG))
print("UNK: " + str(UNK))
#print("b: " + str(b))
print("r: " + str(r))
#print("rArr: " + str(rArr))
print("bTable: " + str(bTable_1))
print("table1: " + str(table1_1))
print("sofsoft: " + str(sofsoft_1))
print("recTable: " + str(recTable_1))


print("\n\n\n")

print("party 2:")
print("p: " + str(p))
print("n: " + str(n))
print("POS: " + str(POS))
print("NEG: " + str(NEG))
print("UNK: " + str(UNK))
#print("b: " + str(b))
print("r: " + str(r))
#print("rArr: " + str(rArr))
print("bTable: " + str(bTable_2))
print("table1: " + str(table1_2))
print("sofsoft: " + str(sofsoft_2))
print("recTable: " + str(recTable_2))
'''





f = open("config_p0_001.csv","w")
f.write("k,l,n,r,b,POS,NEG,UNK,rArr\n")
f.write(str(k) + "," + str(l) + "," + str(n) + "," + str(r) + "," + str(b) + "," + str(POS) + "," + str(NEG) + "," + str(UNK))
for i in range(len(rArr)):
	f.write("," + str(rArr[i]))
f.write("\n")
f.close()

f = open("config_p1_001.csv","w")
f.write("k,l,n,r,POS,NEG,UNK\n")
f.write(str(k) + "," + str(l) + "," + str(n) + "," + str(r_1) + "," + str(POS) + "," + str(NEG) + "," + str(UNK) + "\n")
'''
f.write("k," + str(k) + "\n")
f.write("l," + str(l) + "\n")
f.write("n," + str(n) + "\n")
f.write("r," + str(r_1) + "\n")
f.write("POS," + str(POS) + "\n")
f.write("NEG," + str(NEG) + "\n")
f.write("UNK," + str(UNK) + "\n")
'''
#f.write(str(k) + "," + str(l) + "," + str(n) + "," + str(POS) + "," + str(NEG) + "," + str(UNK))
f.close()

f = open("config_p2_001.csv","w")
f.write("k,l,n,r,POS,NEG,UNK\n")
f.write(str(k) + "," + str(l) + "," + str(n) + "," + str(r_2) + "," + str(POS) + "," + str(NEG) + "," + str(UNK) + "\n")
'''
f.write("k," + str(k) + "\n")
f.write("l," + str(l) + "\n")
f.write("n," + str(n) + "\n")
f.write("r," + str(r_2) + "\n")
f.write("POS," + str(POS) + "\n")
f.write("NEG," + str(NEG) + "\n")
f.write("UNK," + str(UNK) + "\n")
'''
#f.write(str(k) + "," + str(l) + "," + str(n) + "," + str(POS) + "," + str(NEG) + "," + str(UNK))
f.close()


f = open("block1_p0_001.csv","w")
f.write("input,b,output\n")
for i in range(len(bTable)):
	f.write(str(i) + "," + str(bTable[i]) + "," + str(table1[i]) + "\n")
f.close()

f = open("block1_p1_001.csv","w")
f.write("input,b,output\n")
#f.write(str(bTable_1)[1:-1])
for i in range(len(bTable_1)):
	f.write(str(i) + "," + str(bTable_1[i]) + "," + str(table1_1[i]) + "\n")
	#f.write(str(bTable_1[i]) + "\n")
#f.write("table for first block:\n")
#f.write(str(table1_1)[1:-1])
f.close()

f = open("block1_p2_001.csv","w")
f.write("input,b,output\n")
#f.write(str(bTable_2)[1:-1])
for i in range(len(bTable_2)):
	f.write(str(i) + "," + str(bTable_2[i]) + "," + str(table1_2[i]) + "\n")
	#f.write(str(bTable_2[i]) + "\n")
#f.write("table for first block:\n")
#f.write(str(table1_2)[1:-1])
#for i in range(len(table1_2)):
#	f.write(str(i) + "," + str(table1_2[i]) + "\n")
	#f.write(str(table1_2[i]) + "\n")
f.close()


f = open("tables_p0_001.csv","w")
f.write("b,block,input,output\n")
for c in range(len(sofsoft)):
	for co in range(len(sofsoft[c])):
		for cou in range(len(sofsoft_1[c][co])):
			f.write(str(c) + "," + str(co+_sage_const_1 ) + "," + str(cou) + "," + str(sofsoft[c][co][cou]) + "\n")
f.close()

f = open("tables_p1_001.csv","w")
#f.write("b = 0\n")
#tbw = ""
f.write("b,block,input,output\n")
for c in range(len(sofsoft_1)):
	for co in range(len(sofsoft_1[c])):
		for cou in range(len(sofsoft_1[c][co])):
			f.write(str(c) + "," + str(co+_sage_const_1 ) + "," + str(cou) + "," + str(sofsoft_1[c][co][cou]) + "\n")
			#f.write(str(sofsoft_1[c][co][cou]) + "\n")
			#tbw = tbw + str(sofsoft_1[c][co][cou]) + ","
#tbw = tbw[:-1]
#f.write(tbw)
#f.write("block = 2")
f.close()

f = open("tables_p2_001.csv","w")
#f.write("b = 0\n")
#tbw = ""
f.write("b,block,input,output\n")
for c in range(len(sofsoft_2)):
	for co in range(len(sofsoft_2[c])):
		for cou in range(len(sofsoft_2[c][co])):
			f.write(str(c) + "," + str(co+_sage_const_1 ) + "," + str(cou) + "," + str(sofsoft_2[c][co][cou]) + "\n")
			#f.write(str(sofsoft_2[c][co][cou]) + "\n")
			#tbw = tbw + str(sofsoft_2[c][co][cou]) + ","
#tbw = tbw[:-1]
#f.write(tbw)
#f.write("block = 2")
f.close()

f = open("rectable_p0_001.csv", "w")
f.write("input, output\n")
for i in range(len(recTable)):
	tbw = "0"*(k-len(Integer(i).digits(_sage_const_3 )))
	for c in range(len(Integer(i).digits(_sage_const_3 ))-_sage_const_1 , -_sage_const_1 , -_sage_const_1 ):
			tbw = tbw + str(Integer(i).digits(_sage_const_3 )[c])
	f.write(tbw + "," + str(recTable[i]) + "\n")
f.close()

f = open("rectable_p1_001.csv", "w")
f.write("input, output\n")
for i in range(len(recTable_1)):
	tbw = "0"*(k-len(Integer(i).digits(_sage_const_3 )))
	for c in range(len(Integer(i).digits(_sage_const_3 ))-_sage_const_1 , -_sage_const_1 , -_sage_const_1 ):
			tbw = tbw + str(Integer(i).digits(_sage_const_3 )[c])
	f.write(tbw + "," + str(recTable_1[i]) + "\n")
f.close()

f = open("rectable_p2_001.csv", "w")
f.write("input, output\n")
for i in range(len(recTable_2)):
	tbw = "0"*(k-len(Integer(i).digits(_sage_const_3 )))
	for c in range(len(Integer(i).digits(_sage_const_3 ))-_sage_const_1 , -_sage_const_1 , -_sage_const_1 ):
			tbw = tbw + str(Integer(i).digits(_sage_const_3 )[c])
	f.write(tbw + "," + str(recTable_2[i]) + "\n")
f.close()





