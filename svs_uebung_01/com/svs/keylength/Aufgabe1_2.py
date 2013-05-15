import math
keylength = [40,56,64,112,128]
time = []
average = 0
units = 1000000/(10*10)
print("Units: ", units)

print("time:")
for i in keylength:
    average += i
    t = 2**i/(5*10**8)/units/60/60/24
    time.append(t)
    print("\t",i," \t: ",t,"days")

average /= len(time)

t = (2**average)/(5*10**8)/(1000000000/(10*10))/60/60/24

print("\nAverage key length: \t\t",average)
print("decoding time today: \t\t",t)
print("number of years until \ndecoding time is one day: \t",math.log(t,2))
