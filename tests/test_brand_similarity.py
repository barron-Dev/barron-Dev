from cyclothone.brand.similarity import combined_similarity,jaro_winkler,levenshtein
def test_distance():assert levenshtein('acme','acm')==1 and levenshtein('acme','acne')==1
def test_jw():assert jaro_winkler('acme','acme')==1.0 and jaro_winkler('acme','acne')>.8
def test_combined():assert combined_similarity('acme','acme')==1.0 and combined_similarity('acme','acne')>combined_similarity('acme','zzzz')
