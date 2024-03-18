#include "../../include/pkg/voter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/crypto_driver.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"
#include "util.hpp"

/*
Syntax to use logger:
  CUSTOM_LOG(lg, debug) << "your message"
See logger.hpp for more modes besides 'debug'
*/
namespace {
src::severity_logger<logging::trivial::severity_level> lg;
}

/**
 * Constructor
 */
VoterClient::VoterClient(std::shared_ptr<NetworkDriver> network_driver,
                         std::shared_ptr<CryptoDriver> crypto_driver,
                         VoterConfig voter_config, CommonConfig common_config) {
  // Make shared variables.
  this->voter_config = voter_config;
  this->common_config = common_config;
  this->network_driver = network_driver;
  this->crypto_driver = crypto_driver;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();
  initLogger();

  // Load election public key
  try {
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading arbiter public keys; "
                                    "application may be non-functional.");
  }

  // Load registrar public key
  try {
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }

  // Load vote info (vote, zkp, registrar signature, and blind)
  // This is info voter should generate or receive after registering
  try {
    Vote_Ciphertext vote;
    LoadVote(this->voter_config.voter_vote_path, vote);
    this->vote = vote;

    VoteZKP_Struct zkp;
    LoadVoteZKP(this->voter_config.voter_vote_zkp_path, zkp);
    this->vote_zkp = zkp;

    CryptoPP::Integer registrar_signature;
    LoadInteger(this->voter_config.voter_registrar_signature_path,
                registrar_signature);
    this->registrar_signature = registrar_signature;

    CryptoPP::Integer blind;
    LoadInteger(this->voter_config.voter_blind_path, blind);
    this->blind = blind;
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading vote info; voter may still need to register.");
  }
}

/**
 * Run REPL
 */
void VoterClient::run() {
  // Start REPL
  REPLDriver<VoterClient> repl = REPLDriver<VoterClient>(this);
  repl.add_action("register", "register <address> <port> {0, 1}",
                  &VoterClient::HandleRegister);
  repl.add_action("vote", "vote <address> <port>", &VoterClient::HandleVote);
  repl.add_action("verify", "verify", &VoterClient::HandleVerify);
  repl.run();
}

/**
 * Key exchange with either registrar or tallyer
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
VoterClient::HandleKeyExchange(CryptoPP::RSA::PublicKey verification_key) {
  // Generate private/public DH values
  auto dh_values = this->crypto_driver->DH_initialize();

  // Send g^a
  UserToServer_DHPublicValue_Message user_public_value_s;
  user_public_value_s.public_value = std::get<2>(dh_values);
  std::vector<unsigned char> user_public_value_data;
  user_public_value_s.serialize(user_public_value_data);
  this->network_driver->send(user_public_value_data);

  // 2) Receive m = (g^a, g^b) signed by the server
  std::vector<unsigned char> server_public_value_data =
      this->network_driver->read();
  ServerToUser_DHPublicValue_Message server_public_value_s;
  server_public_value_s.deserialize(server_public_value_data);

  // Verify signature
  bool verified = this->crypto_driver->RSA_verify(
      verification_key,
      concat_byteblocks(server_public_value_s.server_public_value,
                        server_public_value_s.user_public_value),
      server_public_value_s.server_signature);
  if (!verified) {
    this->cli_driver->print_warning("Signature verification failed");
    throw std::runtime_error("Voter: failed to verify server signature.");
  }
  if (server_public_value_s.user_public_value != std::get<2>(dh_values)) {
    this->cli_driver->print_warning("Session validation failed");
    throw std::runtime_error(
        "Voter: inconsistencies in voter public DH value.");
  }

  // Recover g^ab
  CryptoPP::SecByteBlock DH_shared_key = crypto_driver->DH_generate_shared_key(
      std::get<0>(dh_values), std::get<1>(dh_values),
      server_public_value_s.server_public_value);
  CryptoPP::SecByteBlock AES_key =
      crypto_driver->AES_generate_key(DH_shared_key);
  CryptoPP::SecByteBlock HMAC_key =
      crypto_driver->HMAC_generate_key(DH_shared_key);
  return std::make_pair(AES_key, HMAC_key);
}

/**
 * Handle registering with the registrar. This function:
 * 1) Handle key exchange.
 * 2) ElGamal encrypt the raw vote and generate a ZKP for it
 *    through `ElectionClient::GenerateVote`.
 * 2) Blind the vote and send it to the registrar.
 * 3) Receive the blind signature from the registrar and save it.
 * 3) Receives and saves the signature from the server.
 */
void VoterClient::HandleRegister(std::string input) {
  // Parse input and connect to registrar
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 4) {
    this->cli_driver->print_warning("usage: register <address> <port> <vote>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Load some info from config into variables
  std::string voter_id = this->voter_config.voter_id;
  CryptoPP::Integer raw_vote = CryptoPP::Integer(std::stoi(args[3]));
  
  // Handle key exchange with the registrar
  auto [aes_key, hmac_key] = HandleKeyExchange(this->RSA_registrar_verification_key);
  
  // Encrypt raw vote and send a ZKP for it through ElectionClient::GenerateVote
  auto [encrypted_vote, vote_zkp] = ElectionClient::GenerateVote(raw_vote, EG_arbiter_public_key);
  
  // Blind the vote and send it to the registrar
  VoterToRegistrar_Register_Message vote_msg;
  auto [blinded_vote, blinding_factor] = this->crypto_driver->RSA_BLIND_blind(this->RSA_registrar_verification_key, encrypted_vote);
  vote_msg.vote = blinded_vote;
  auto vote_msg_bytes = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &vote_msg);
  network_driver->send(vote_msg_bytes);
  
  // Receive the blind signature from the registrar
  std::vector<unsigned char> reg_to_voter_blind_sig_data = network_driver->read();
  RegistrarToVoter_Blind_Signature_Message reg_to_voter_blind_sig_msg;
  auto [decrypted_blind_sig_msg_data, blind_sig_msg_decrypted] = crypto_driver->decrypt_and_verify(aes_key, hmac_key, reg_to_voter_blind_sig_data);
  if (!blind_sig_msg_decrypted) {
    throw std::runtime_error("Could not decrypt message");
  }
  reg_to_voter_blind_sig_msg.deserialize(decrypted_blind_sig_msg_data);
  
  // Receive the signature from the server
  std::vector<unsigned char> dh_pub_msg_data = network_driver->read();
  ServerToUser_DHPublicValue_Message dh_pub_msg;
  auto [decrypted_dh_pub_msg, dh_pub_msg_decrypted] = crypto_driver->decrypt_and_verify(aes_key, hmac_key, dh_pub_msg_data);
  if (!dh_pub_msg_decrypted) {
    throw std::runtime_error("Could not decrypt message");
  }
  dh_pub_msg.deserialize(decrypted_dh_pub_msg);

  // Save the ElGamal encrypted vote, ZKP, registrar signature, and blind to both memory and disk
  this->vote = encrypted_vote;
  this->vote_zkp = vote_zkp;
  this->registrar_signature = reg_to_voter_blind_sig_msg.registrar_signature;
  this->blind = blinding_factor;
  SaveVote(this->voter_config.voter_vote_path, encrypted_vote);
  SaveVoteZKP(this->voter_config.voter_vote_zkp_path, vote_zkp);
  SaveInteger(this->voter_config.voter_registrar_signature_path,
              reg_to_voter_blind_sig_msg.registrar_signature);
  SaveInteger(this->voter_config.voter_blind_path, blind);

  this->cli_driver->print_info(
      "Voter registered! Vote saved at " + this->voter_config.voter_vote_path +
      " and vote zkp saved at " + this->voter_config.voter_vote_zkp_path);
  this->network_driver->disconnect();
}

/**
 * Handle voting with the tallyer. This function:
 * 1) Handles key exchange.
 * 2) Unblinds the registrar signature that is stored in `this->registrar_signature`.
 * 3) Sends the vote, ZKP, and unblinded signature to the tallyer.
 */
void VoterClient::HandleVote(std::string input) {
  // Parse input and connect to tallyer
  std::vector<std::string> args = string_split(input, ' ');
  if (args.size() != 3) {
    this->cli_driver->print_warning("usage: vote <address> <port>");
    return;
  }
  this->network_driver->connect(args[1], std::stoi(args[2]));

  // Handles key exchange
  auto [aes_key, hmac_key] = HandleKeyExchange(this->RSA_tallyer_verification_key);

  // Unblinds the registrar signature that is stored in this->registrar_signature
  auto unblinded_sig = this->crypto_driver->RSA_BLIND_unblind(this->RSA_tallyer_verification_key, this->registrar_signature, this->blind);

  // Sends the vote, ZKP, and unblinded signature to the tallyer.
  VoterToTallyer_Vote_Message voter_to_tallyer_msg;
  voter_to_tallyer_msg.unblinded_signature = unblinded_sig;
  voter_to_tallyer_msg.vote = this->vote;
  voter_to_tallyer_msg.zkp = this->vote_zkp;
  auto voter_to_tallyer_msg_bytes = crypto_driver->encrypt_and_tag(aes_key, hmac_key, &voter_to_tallyer_msg);
  network_driver->send(voter_to_tallyer_msg_bytes);

  // Exit cleanly.
  this->network_driver->disconnect();
}

/**
 * Handle verifying the results of the election.
 */
void VoterClient::HandleVerify(std::string input) {
  // Verify
  this->cli_driver->print_info("Verifying election results...");
  auto result = this->DoVerify();

  // Error if election failed
  if (!std::get<2>(result)) {
    this->cli_driver->print_warning("Election failed!");
    throw std::runtime_error("Election failed!");
  }

  // Print results
  this->cli_driver->print_success("Election succeeded!");
  this->cli_driver->print_success("Number of votes for 0: " +
                                  CryptoPP::IntToString(std::get<0>(result)));
  this->cli_driver->print_success("Number of votes for 1: " +
                                  CryptoPP::IntToString(std::get<1>(result)));
}

/**
 * Handle verifying the results of the election. This function
 * 1) Verifies all vote ZKPs and their signatures
 * 2) Verifies all partial decryption ZKPs
 * 3) Combines the partial decryptions to retrieve the final result
 * 4) Returns a tuple of <0-votes, 1-votes, success>
 * If a vote is invalid, simply ignore it: do not throw an error.
 */
std::tuple<CryptoPP::Integer, CryptoPP::Integer, bool> VoterClient::DoVerify() {
  
  // Get a vector of all votes
  auto all_votes = this->db_driver->all_votes();
  
  // Verify all vote ZKPs and their signatures
  std::vector<VoteRow> valid_votes;
  for (size_t i = 0; i < all_votes.size(); ++i) {
    auto current_vote = all_votes[i].vote;
    auto vote_zkp = all_votes[i].zkp;
    bool vote_zkp_verified = ElectionClient::VerifyVoteZKP(std::make_pair(current_vote, vote_zkp), this->EG_arbiter_public_key);
    
    // If the vote is valid, add it to a vector
    if (vote_zkp_verified) {
      valid_votes.push_back(all_votes[i]);
    }
  }
  // Verify all partial decryption ZKPs
  std::vector<PartialDecryptionRow> valid_partial_decryptions;
  auto all_partial_decryption_ZKPs = this->db_driver->all_partial_decryptions();
  for (int i = 0; i < all_partial_decryption_ZKPs.size(); ++i) {
    auto current_partial_decryption_zkp = all_partial_decryption_ZKPs[i];
    CryptoPP::Integer pki;
    LoadInteger(current_partial_decryption_zkp.arbiter_vk_path, pki);
    bool partial_decrypt_zkp_verified = ElectionClient::VerifyPartialDecryptZKP(current_partial_decryption_zkp, pki);
    if (!partial_decrypt_zkp_verified) {
      throw std::runtime_error("Partial decryption ZKP was invalid");
      return std::make_tuple(0, 0, false);
    }
    else {
      valid_partial_decryptions.push_back(current_partial_decryption_zkp);
    }
  } 

  // Combines partial decryptions to retrieve final result
  auto combined_vote = ElectionClient::CombineVotes(valid_votes);
  auto m = ElectionClient::CombineResults(combined_vote, valid_partial_decryptions);

  CryptoPP::Integer num_one_votes = m;
  CryptoPP::Integer num_zero_votes = valid_votes.size() - num_one_votes;
  return std::make_tuple(num_zero_votes, num_one_votes, true);
}
