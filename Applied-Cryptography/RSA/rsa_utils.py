
# Euclidean algorithm to compute the GCD of two integers
def gcd(a, b):
    while a != 0:
            a, b = b % a, a
    return b


def findModInverse(a, m):
    if gcd(a, m) != 1:
        return None # no mod inverse exists if a and m are not relatively prime
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def factorize(n):
	n2 = int(n/2)
	fn = []
	for x in range(2,n2+1):
		if n%x == 0:
			fn.append(x) #lower member of factor pair
			fn.append(n/x) #upper member of factor pair
	print('N has the following factors: '+str(fn))
