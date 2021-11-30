#basic param
#n = 64
k = 8
l = 8
n = k*l

#generated basic param
#p = random_prime(2^n-1, false, 2^(n-1))
p = 2^n
#F = Integers(p)
F = Integers(2^n)
F2 = Integers(2^n)
#F2 = Integers(2)
F3 = Integers(2^n)
#F3 = Integers(3)


#ENUM for output
POS = Integers(3)(1)
NEG = Integers(3)(2)
UNK = Integers(3)(0)

#Random values
r = F.random_element()
#r = F(123)
b = int(Integers(2).random_element())
#b = 0
rArr = [[]]*k
for i in range(k):
	rArr[i] = Integers(3).random_element()
	#rArr[i] = Integers(3)(0)

#Function tables
table1 = [rArr[0]]*(2^l)
bTable = [b]*(2^l)
sofsoft = [ [[]]*(k-1) ,  [[]]*(k-1)]
for i in range(k-1):
	sofsoft[0][i] = [rArr[i+1]]*(2^l)
	sofsoft[1][i] = [rArr[i+1]]*(2^l)

Unk0 = ""
Unk1 = ""
end1 = 0
end2 = int(p/2)



#Begin filling the function tables

#first block
for i in range(2^l):
	inp = "0"*(l-len(bin(i)[2:])) + bin(i)[2:]
	res = UNK
	minstr = inp + "0"*(n-len(inp))
	minv = int(minstr, 2)
	if minv >= p:
		res = (int)(Integers(3).random_element())
		res = 0
		table1[i] += res
		continue
	maxstr = inp + "1"*(n-len(inp))
	maxv = min(int(maxstr, 2), p-1)
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
		bTable[i] = 1-b
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
for i in range(k-1):
	for j in range(2^l):
		inp = "0"*(l-len(bin(j)[2:])) + bin(j)[2:]
		#Unk0
		if len(Unk0)/l < i+1:
			break
		#Function to determine results
		Unk = Unk0
		res = UNK
		minstr = Unk + inp + "0"*(n-len(Unk+inp))
		minv = int(minstr, 2)
		if minv >= p:
			res = (int)(Integers(3).random_element())
			res = 0
			sofsoft[b][i][j] += res
			continue
		maxstr = Unk + inp + "1"*(n-len(Unk+inp))
		maxv = min(int(maxstr, 2), p-1)
		
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
	
	for j in range(2^l):
		inp = "0"*(k-len(bin(j)[2:])) + bin(j)[2:]
		#Unk1
		if len(Unk1)/l < i+1:
			break
		#Function to determine results
		Unk = Unk1
		res = UNK
		minstr = Unk + inp + "0"*(n-len(Unk+inp))
		minv = int(minstr, 2)
		if minv >= p:
			res = (int)(Integers(3).random_element())
			res = 0
			sofsoft[1-b][i][j] += res
			continue
		maxstr = Unk + inp + "1"*(n-len(Unk+inp))
		maxv = min(int(maxstr, 2), p-1)
		
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
		
		sofsoft[1-b][i][j] += res


recTable = [F(0)]*(3^k)
#UnkStr = ""
#for i in range(k):
#	UnkStr = str(UNK - rArr[i]) + UnkStr
#print(UnkStr)
for i in range(k):
	negstr = ""
	for j in range(i):
		negstr = negstr + str(UNK - rArr[j])
	negstr = negstr + str(NEG - rArr[i])
	
	for j in range(3^(k-1-i)):
		tailstr = "0"*(k-1-i-len(Integer(j).digits(3)))
		for c in range(len(Integer(j).digits(3))-1, -1, -1):
			tailstr = tailstr + str(Integer(j).digits(3)[c])
		recTable[int(negstr + tailstr, 3)] = F(1)

'''
for i in range(3^k):
	s = "0"*(k-len(Integer(i).digits(3)))
	for j in range(len(Integer(i).digits(3))-1, -1, -1):
		s = s + str(Integer(i).digits(3)[j])
	print(s + "\t" + str(recTable[i]))
'''

#Secret Sharing the Tables
bTable_1 = [F2(0)]*(2^l)
bTable_2 = [F2(0)]*(2^l)
for i in range(2^l):
	a = int(F2.random_element())
	bTable_2[i] = a
	bTable_1[i] = F2(int(bTable[i])) - a

table1_1 = [F3(0)]*(2^l)
table1_2 = [F3(0)]*(2^l)
for i in range(2^l):
	a = F3.random_element()
	table1_2[i] = a
	table1_1[i] = F3(int(table1[i])) - a

sofsoft_1 = [ [[]]*(k-1) ,  [[]]*(k-1)]
sofsoft_2 = [ [[]]*(k-1) ,  [[]]*(k-1)]
for i in range(k-1):
	sofsoft_1[0][i] = [F3(0)]*(2^l)
	sofsoft_1[1][i] = [F3(0)]*(2^l)
	sofsoft_2[0][i] = [F3(0)]*(2^l)
	sofsoft_2[1][i] = [F3(0)]*(2^l)
for i in range(k-1):
	for j in range(2^l):
		a = F3.random_element()
		sofsoft_2[0][i][j] = a
		sofsoft_1[0][i][j] = F3(int(sofsoft[0][i][j])) - a
		a = F3.random_element()
		sofsoft_2[1][i][j] = a
		sofsoft_1[1][i][j] = F3(int(sofsoft[0][i][j])) - a

recTable_1 = [F(0)]*(3^k)
recTable_2 = [F(0)]*(3^k)
for i in range(3^k):
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


f = open("tables_p1_001.csv","w")
#f.write("b = 0\n")
#tbw = ""
f.write("b,block,input,output\n")
for c in range(len(sofsoft_1)):
	for co in range(len(sofsoft_1[c])):
		for cou in range(len(sofsoft_1[c][co])):
			f.write(str(c) + "," + str(co+1) + "," + str(cou) + "," + str(sofsoft_1[c][co][cou]) + "\n")
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
			f.write(str(c) + "," + str(co+1) + "," + str(cou) + "," + str(sofsoft_2[c][co][cou]) + "\n")
			#f.write(str(sofsoft_2[c][co][cou]) + "\n")
			#tbw = tbw + str(sofsoft_2[c][co][cou]) + ","
#tbw = tbw[:-1]
#f.write(tbw)
#f.write("block = 2")
f.close()

f = open("rectable_p1_001.csv", "w")
f.write("input, output\n")
for i in range(len(recTable_1)):
	tbw = "0"*(k-len(Integer(i).digits(3)))
	for c in range(len(Integer(i).digits(3))-1, -1, -1):
			tbw = tbw + str(Integer(i).digits(3)[c])
	f.write(tbw + "," + str(recTable_1[i]) + "\n")
f.close()

f = open("rectable_p2_001.csv", "w")
f.write("input, output\n")
for i in range(len(recTable_2)):
	tbw = "0"*(k-len(Integer(i).digits(3)))
	for c in range(len(Integer(i).digits(3))-1, -1, -1):
			tbw = tbw + str(Integer(i).digits(3)[c])
	f.write(tbw + "," + str(recTable_2[i]) + "\n")
f.close()




