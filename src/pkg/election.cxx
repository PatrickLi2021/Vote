#include "../../include/pkg/election.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/constants.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Generate Vote and ZKP.
 */
std::pair<Vote_Ciphertext, VoteZKP_Struct>
ElectionClient::GenerateVote(CryptoPP::Integer vote, CryptoPP::Integer pk) {
  initLogger();
  std::cout << "inside generatevote";
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer r(rng, 2, DL_Q - 1);
  
  // Populate the Vote_Ciphertext struct
  Vote_Ciphertext vote_cipher;
  if (vote == 0) {
    vote_cipher.b = CryptoPP::ModularExponentiation(pk, r, DL_P);
  }
  else {
    auto g_to_vote = CryptoPP::ModularExponentiation(DL_G, vote, DL_P);
    auto pk_to_r = CryptoPP::ModularExponentiation(pk, r, DL_P);
    vote_cipher.b = a_times_b_mod_c(g_to_vote, pk_to_r, DL_P);
  }
  vote_cipher.a = CryptoPP::ModularExponentiation(DL_G, r, DL_P);

  // Populate VoteZKP_Struct
  VoteZKP_Struct vote_zkp;
  CryptoPP::Integer r0(rng, 2, DL_Q - 1);
  
  if (vote == 0) {
    // Randomly sample r_1" and sigma_1/c_1
    CryptoPP::Integer r_double_prime_1(rng, 2, DL_Q - 1);
    vote_zkp.r1 = r_double_prime_1;
    CryptoPP::Integer sigma_1(rng, 2, DL_Q - 1);
    vote_zkp.c1 = sigma_1;
    
    // Calculate b' = b/g^1 (mod p)
    auto b_prime = a_times_b_mod_c(vote_cipher.b, CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P);

    // Calculate a1 = g^r1" / a^sigma1 (mod p)
    auto g_to_r1 = CryptoPP::ModularExponentiation(DL_G, vote_zkp.r1, DL_P);
    auto a_to_sigma1_inverse = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(vote_cipher.a, vote_zkp.c1, DL_P), DL_P);
    vote_zkp.a1 = a_times_b_mod_c(g_to_r1, a_to_sigma1_inverse, DL_P);
    
    // Calculate b1 = pk^(r1") / (b')^c1 (mod p)
    auto pk_to_r1_double_prime_mod_p = CryptoPP::ModularExponentiation(pk, r_double_prime_1, DL_P);
    auto b_prime_to_c1_inverse_mod_p = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(b_prime, vote_zkp.c1, DL_P), DL_P);
    vote_zkp.b1 = a_times_b_mod_c(pk_to_r1_double_prime_mod_p, b_prime_to_c1_inverse_mod_p, DL_P);

    // Calculate a0 = g^r'0 (mod p) and b0 = pk^r'0 mod p
    CryptoPP::Integer r_prime_0(rng, 2, DL_Q - 1);
    vote_zkp.a0 = CryptoPP::ModularExponentiation(DL_G, r_prime_0, DL_P);
    vote_zkp.b0 = CryptoPP::ModularExponentiation(pk, r_prime_0, DL_P);
    
    // Calculate sigma or c = H(pk, a, b, a'0, b'0, a'1, b'1)
    auto sigma = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, vote_zkp.a0, vote_zkp.b0, vote_zkp.a1, vote_zkp.b1);
    // Calculate sigma0 or c0 = sigma1 - sigma (mod q)
    vote_zkp.c0 = (sigma - vote_zkp.c1) % DL_Q;
    // Calculate r0" = r'0 + c0 * r (mod q)
    vote_zkp.r0 = r_prime_0 + a_times_b_mod_c(vote_zkp.c0, r, DL_Q);
  }
  else {
    // Compute and set c0 and r0
    CryptoPP::Integer c0(rng, 2, DL_Q - 1);
    vote_zkp.c0 = c0;
    CryptoPP::Integer r_double_prime_0(rng, 2, DL_Q - 1);
    vote_zkp.r0 = r_double_prime_0;

    // Compute and set a0 in struct
    auto g_to_r_double_prime_0 = CryptoPP::ModularExponentiation(DL_G, vote_zkp.r0, DL_P);
    auto a_to_c0_inverse = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(vote_cipher.a, vote_zkp.c0, DL_P), DL_P);
    vote_zkp.a0 = a_times_b_mod_c(g_to_r_double_prime_0, a_to_c0_inverse, DL_P);

    // Compute and set b0 in struct
    auto pk_to_r_double_prime_0 = CryptoPP::ModularExponentiation(pk, vote_zkp.r0, DL_P);
    auto b_to_c0_inverse = CryptoPP::EuclideanMultiplicativeInverse(CryptoPP::ModularExponentiation(vote_cipher.b, vote_zkp.c0, DL_P), DL_P);
    vote_zkp.b0 = a_times_b_mod_c(pk_to_r_double_prime_0, b_to_c0_inverse, DL_P);

    // Compute and set a1 and b1 in struct
    CryptoPP::Integer r_1_prime(rng, 2, DL_Q - 1);
    vote_zkp.a1 = CryptoPP::ModularExponentiation(DL_G, r_1_prime, DL_P);
    vote_zkp.b1 = CryptoPP::ModularExponentiation(pk, r_1_prime, DL_P);
    
    // Get the challenge/sigma and compute c1
    auto sigma = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, vote_zkp.a0, vote_zkp.b0, vote_zkp.a1, vote_zkp.b1);
    vote_zkp.c1 = (sigma - vote_zkp.c0) % DL_Q;
  
    // Compute r1
    vote_zkp.r1 = r_1_prime + a_times_b_mod_c(vote_zkp.c1, r, DL_Q);
  }
  std::cout << "leaving generatevote";
  return std::make_pair(vote_cipher, vote_zkp);
}


/**
 * Verify vote zkp.
 */
bool ElectionClient::VerifyVoteZKP(
    std::pair<Vote_Ciphertext, VoteZKP_Struct> vote, CryptoPP::Integer pk) {
  std::cout << "inside verifyvotezkp";
  initLogger();
  auto [vote_cipher, vote_zkp] = vote;

  // Verify that g^(r"0) = a0' * a^(c0) (mod p) and pk^(r"0) = b0 * b^(c0) (mod p)
  auto g_to_r_double_prime_0 = CryptoPP::ModularExponentiation(DL_G, vote_zkp.r0, DL_P);
  auto a0_times_a_to_c0 = a_times_b_mod_c(vote_zkp.a0, CryptoPP::ModularExponentiation(vote_cipher.a, vote_zkp.c0, DL_P), DL_P);
  auto statement_1 = g_to_r_double_prime_0 == a0_times_a_to_c0;
  
  // Verify that g^(r"1) = A1 * c1^(sigma1) and pk^(r"1) = B1 * (c2 / g)^(sigma1)
  auto g_to_r_double_prime_1 = CryptoPP::ModularExponentiation(DL_G, vote_zkp.r1, DL_P);
  auto a1_times_a_to_c1 = a_times_b_mod_c(vote_zkp.a1, CryptoPP::ModularExponentiation(vote_cipher.a, vote_zkp.c1, DL_P), DL_P);
  auto statement_2 = g_to_r_double_prime_1 == a1_times_a_to_c1;

  // Verify that pk^(r"0) = b'0 * b^(c0) (mod p)
  auto pk_to_r_double_prime_0 = CryptoPP::ModularExponentiation(pk, vote_zkp.r0, DL_P);
  auto b0_times_b_to_c0 = a_times_b_mod_c(vote_zkp.b0, CryptoPP::ModularExponentiation(vote_cipher.b, vote_zkp.c0, DL_P), DL_P);
  auto statement_3 = pk_to_r_double_prime_0 == b0_times_b_to_c0;
  
  // Verify that pk^(r_1") = b'1 * (b/g^1)^(c1) (mod p)
  // TODO
  auto pk_to_r_double_prime_1 = CryptoPP::ModularExponentiation(pk, vote_zkp.r1, DL_P);
  auto b_div_g_to_c1 = CryptoPP::ModularExponentiation(a_times_b_mod_c(vote_cipher.b, CryptoPP::EuclideanMultiplicativeInverse(DL_G, DL_P), DL_P), vote_zkp.c1, DL_P);
  auto b1_times_b_div_g_to_c1 = a_times_b_mod_c(vote_zkp.b1, b_div_g_to_c1, DL_P);
  auto statement_4 = pk_to_r_double_prime_1 == b1_times_b_div_g_to_c1;

  // Verify that sigma0 + sigma1 = sigma (mod q)
  auto hash_value = hash_vote_zkp(pk, vote_cipher.a, vote_cipher.b, vote_zkp.a0, vote_zkp.b0, vote_zkp.a1, vote_zkp.b1) % DL_Q;
  auto c0_plus_c1 = (vote_zkp.c0 + vote_zkp.c1) % DL_Q;
  auto statement_5 = c0_plus_c1 == hash_value;
  std::cout << "leaving verifyvotezkp";
  if (statement_1 && statement_2 && statement_3 && statement_4 && statement_5) {
    return true;
  }
  return false;
}

/**
 * Generate partial decryption and zkp.
 */
std::pair<PartialDecryption_Struct, DecryptionZKP_Struct>
ElectionClient::PartialDecrypt(Vote_Ciphertext combined_vote,
                               CryptoPP::Integer pk, CryptoPP::Integer sk) {
  initLogger();
  std::cout << "inside partialdecrypt";
  // Instantiate PartialDecryption_Struct and DecryptionZKP_Struct
  PartialDecryption_Struct partial_dec;
  DecryptionZKP_Struct decryption_zkp;
  
  // Pick a random r from Zq
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::Integer r(rng, 2, DL_Q - 1);
  
  // Compute (u, v)
  decryption_zkp.u = CryptoPP::ModularExponentiation(combined_vote.a, r, DL_P);
  decryption_zkp.v = CryptoPP::ModularExponentiation(DL_G, r, DL_P);

  // Compute a challenge c using the hash function
  auto c = hash_dec_zkp(pk, combined_vote.a, combined_vote.b, decryption_zkp.u, decryption_zkp.v);

  // Let s := r + c * ski (mod q) and compute decryption factor d := a^ski (mod p)
  decryption_zkp.s = (r + a_times_b_mod_c(c, sk, DL_Q)) % DL_Q;
  
  partial_dec.d = CryptoPP::ModularExponentiation(combined_vote.a, sk, DL_P);
  partial_dec.aggregate_ciphertext = combined_vote;
  std::cout << "leaving partialdecrypt";
  return std::make_pair(partial_dec, decryption_zkp);
}

/**
 * Verify partial decryption zkp.
 */
bool ElectionClient::VerifyPartialDecryptZKP(
    ArbiterToWorld_PartialDecryption_Message a2w_dec_s, CryptoPP::Integer pki) {
  initLogger();
  std::cout << "inside verifypartialdecryptzkp";
  // Re-compute sigma
  auto c = hash_dec_zkp(pki, a2w_dec_s.dec.aggregate_ciphertext.a, a2w_dec_s.dec.aggregate_ciphertext.b, a2w_dec_s.zkp.u, a2w_dec_s.zkp.v);
  
  // Verify that g^s = v * pki^(sigma) (mod p) (page 32 of book)
  auto g_to_s = CryptoPP::ModularExponentiation(DL_G, a2w_dec_s.zkp.s, DL_P);
  auto pk_to_c = CryptoPP::ModularExponentiation(pki, c, DL_P);
  auto v_times_pk_to_c = a_times_b_mod_c(a2w_dec_s.zkp.v, pk_to_c, DL_P);
  auto statement_1 = g_to_s == v_times_pk_to_c;

  // Verify that a^s = u * d^(sigma) (mod p)
  auto a_to_s = CryptoPP::ModularExponentiation(a2w_dec_s.dec.aggregate_ciphertext.a, a2w_dec_s.zkp.s, DL_P);
  auto d_to_c = CryptoPP::ModularExponentiation(a2w_dec_s.dec.d, c, DL_P);
  auto u_times_d_to_c = a_times_b_mod_c(a2w_dec_s.zkp.u, d_to_c, DL_P);
  auto statement_2 = a_to_s == u_times_d_to_c;
  std::cout << "leaving verifypartialdecryptzkp";
  if (statement_1 && statement_2) {
    return true;
  }
  return false;
}

/**
 * Combine votes into one using homomorphic encryption.
 */
Vote_Ciphertext ElectionClient::CombineVotes(std::vector<VoteRow> all_votes) {
  initLogger();
  std::cout << "inside combinevotes";
  Vote_Ciphertext vote_cipher;
  CryptoPP::Integer c1_product = 1;
  CryptoPP::Integer c2_product = 1;
  
  // Multiply each c1 with each other
  for (int i = 0; i < all_votes.size(); ++i) {
    c1_product *= a_times_b_mod_c(all_votes[i].vote.a, c1_product, DL_P);
    c2_product *= a_times_b_mod_c(all_votes[i].vote.b, c2_product, DL_P);
  }
  vote_cipher.a = c1_product;
  vote_cipher.b = c2_product;
  std::cout << "leaving combinedvotes";
  return vote_cipher;
}

/**
 * Combine partial decryptions into final result.
 */
CryptoPP::Integer ElectionClient::CombineResults(
    Vote_Ciphertext combined_vote,
    std::vector<PartialDecryptionRow> all_partial_decryptions) {
  initLogger();
  std::cout << "inside combineresults";
  CryptoPP::Integer product_c1_ski = 1;
  // Compute c1^(ski)
  for (int i = 0; i < all_partial_decryptions.size(); ++i) {
    product_c1_ski = a_times_b_mod_c(product_c1_ski, all_partial_decryptions[i].dec.d, DL_P);
  }
  // Calculate g^m
  auto g_to_m = a_times_b_mod_c(combined_vote.b, CryptoPP::EuclideanMultiplicativeInverse(product_c1_ski, DL_P), DL_P);

  // Brute force search to find m
  CryptoPP::Integer m = 0;
  CryptoPP::Integer current_val = a_exp_b_mod_c(DL_G, m, DL_P);
  while (current_val != g_to_m) {
    m += 1;
    current_val = a_exp_b_mod_c(DL_G, m, DL_P);
  }
  std::cout << "leaving combineresults";
  return m;
}