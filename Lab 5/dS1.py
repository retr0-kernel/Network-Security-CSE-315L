from py_ecc.bls import G2ProofOfPossession as bls_pop

private_keys = [5566, 1234, 9876]
public_keys = [bls_pop.SkToPk(key) for key in private_keys]
message = b'\xab' * 32
signatures = [bls_pop.Sign(key, message) for key in private_keys]
agg_signature = bls_pop.Aggregate(signatures)
assert bls_pop.FastAggregateVerify(public_keys, message, agg_signature)

print("Digital signature simulation successful!")
