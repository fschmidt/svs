import math
keylength = [40.0,56,64,112,128]
time = []
average = 0
units = 1000000/(10*10)
print("Units: ", units)

for i in keylength:
    average += i
    t = 2**i/(5*10**8)/units/60/60/24
    time.append(t)
    print(i," \t: ",t,"days")

average /= len(time)

t = (2**average)/(5*10**8)/(1000000000/(10*10))/60/60/24

print(average)
print(t)
print(math.log(t,2))
