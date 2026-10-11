"""Exact arithmetic premises for the two Pasta SWU branch-cover arguments.

This checks polynomial identities and finite-field hypotheses, not Weil's theorem.
No external code, parameter artifact, curve enumeration or cryptographic proof.
"""
import auxiliary as a

def derivative(poly):
    return [i*poly[i] for i in range(1, len(poly))]


def model_identity(p, A, B, numerator, denominator, scale, model):
    """Clear denominators and check the whole curve/model identity."""
    gx = a.add(a.add(a.power(numerator,3,p),
                    a.mul([A],a.mul(numerator,a.power(denominator,2,p),p),p),p),
               a.mul([B],a.power(denominator,3,p),p),p)
    left = a.mul(gx,a.power(scale,2,p),p)
    right = a.mul(model,a.power(denominator,3,p),p)
    a.require(a.add(left,right,p,-1) == [], 'exact model identity')


def build_models(p, A, B, Z):
    t = [0,0,Z]
    v = a.add(t,[1],p)
    ta = a.add(a.power(t,2,p),t,p)
    phi = a.add(a.mul([B*B],a.power(a.add(ta,[1],p),3,p),p),
                a.mul([A**3],a.power(ta,2,p),p),p)
    common = a.mul(v,phi,p)
    d1,d2 = -A**3*B*Z**3 % p, -A**3*B % p
    h1,h2 = a.mul([d1],common,p),a.mul([d2],common,p)
    n1 = a.mul([B],a.add(ta,[1],p),p)
    n2 = a.mul([-B],a.add(ta,[1],p),p)
    denominator1,denominator2 = a.mul([-A],ta,p),a.mul([A],v,p)
    scale1 = a.mul([0,0,0,A**3*Z**3],a.power(v,2,p),p)
    scale2 = a.mul([A**3],a.power(v,2,p),p)
    return dict(t=t,v=v,ta=ta,phi=phi,common=common,d1=d1,d2=d2,
                h1=h1,h2=h2,n1=n1,n2=n2,denominator1=denominator1,
                denominator2=denominator2,scale1=scale1,scale2=scale2)


def certify(p, A, B, Z):
    """Return exact checked premises; p's primality is established by the caller."""
    a.require(p > 3 and p % 4 == 1, 'odd characteristic and square minus one')
    a.require(0 < A < p and 0 < B < p and 0 < Z < p, 'canonical nonzero constants')
    a.require(Z != p-1 and pow(Z,(p-1)//2,p) == p-1, 'nonexceptional nonsquare Z')
    a.require(pow(-A*B % p,(p-1)//2,p) == p-1, 'nonsquare negative AB')
    a.require((4*A**3+27*B*B) % p != 0, 'nonsingular auxiliary curve')
    data = build_models(p,A,B,Z)
    for name, degree in [('phi',12),('h1',14),('h2',14)]:
        poly = data[name]
        a.require(len(poly) == degree+1, 'exact degree '+name)
        a.require(a.gcd(poly,derivative(poly),p) == [1], 'squarefree '+name)
    a.require(a.gcd(data['phi'],data['v'],p) == [1], 'disjoint branch factors')
    a.require(data['phi'][0] == B*B % p, 'nonzero zero-input fiber')
    for j in (1,2):
        model_identity(p,A,B,data['n'+str(j)],data['denominator'+str(j)],
                       data['scale'+str(j)],data['h'+str(j)])
    # Native nonzero inputs never hit the removed t=-1 branch.
    a.require(pow(-pow(Z,-1,p) % p,(p-1)//2,p) == p-1, 'no rational t=-1')
    # H1 has its two rational boundary points at zero, H2 at infinity.
    euler = lambda x: pow(x % p,(p-1)//2,p)
    boundary = [euler(data['h1'][0]),euler(data['h1'][-1]),
                euler(data['h2'][0]),euler(data['h2'][-1])]
    a.require(boundary == [1,p-1,p-1,1], 'exact rational boundary fibers')
    w0_y_squared = -pow(B*pow(A,-1,p) % p,3,p) % p
    a.require(w0_y_squared != 0, 'geometric w-zero points have nonzero ordinate')
    a.require(euler(w0_y_squared) == p-1, 'no rational w-zero fiber')
    return {'p':str(p),'A':str(A),'B':B,'Z':str(Z),'phi_degree':12,
            'model_degrees':[14,14],'squarefree_models':True,
            'cleared_model_identities':True,'negative_AB_nonsquare':True,
            'rational_boundary_fibers':['C1:u=0:two','C2:u=infinity:two'],
            'w0_geometric_ordinate_nonzero':True,
            'geometry_interpretation':'Genus and ramification follow from the separately cited curve theorems; not executed geometry software.'}
