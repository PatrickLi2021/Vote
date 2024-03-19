#include "../../include/pkg/arbiter.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/election.hpp"

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
ArbiterClient::ArbiterClient(ArbiterConfig arbiter_config,
                             CommonConfig common_config) {
  // Make shared variables.
  this->cli_driver->print_left("inside arbiter client");
  this->arbiter_config = arbiter_config;
  this->common_config = common_config;
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = std::make_shared<CryptoDriver>();
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(this->common_config.db_path);
  this->db_driver->init_tables();
  this->cli_driver->init();

  // Load arbiter keys.
  try {
    LoadInteger(arbiter_config.arbiter_secret_key_path,
                this->EG_arbiter_secret_key);
    LoadInteger(arbiter_config.arbiter_public_key_path,
                this->EG_arbiter_public_key_i);
    LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                          this->EG_arbiter_public_key);
    this->cli_driver->print_left("inside arbiter loading keys");
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find arbiter keys; you might consider generating some!");
  }

  // Load registrar public key
  try {
    this->cli_driver->print_left("inside arbiter client load registrar public key");
    LoadRSAPublicKey(common_config.registrar_verification_key_path,
                     this->RSA_registrar_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading registrar public key; "
                                    "application may be non-functional.");
  }

  // Load tallyer public key
  try {
    this->cli_driver->print_left("load tallyer public key");
    LoadRSAPublicKey(common_config.tallyer_verification_key_path,
                     this->RSA_tallyer_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Error loading tallyer public key; application may be non-functional.");
  }
}

void ArbiterClient::run() {
  // Start REPL
  REPLDriver<ArbiterClient> repl = REPLDriver<ArbiterClient>(this);
  repl.add_action("keygen", "keygen", &ArbiterClient::HandleKeygen);
  this->cli_driver->print_left("inside arbiter client run");
  repl.add_action("adjudicate", "adjudicate", &ArbiterClient::HandleAdjudicate);
  repl.run();
}

/**
 * Handle generating election keys
 */
void ArbiterClient::HandleKeygen(std::string _) {
  // Generate keys
  this->cli_driver->print_info("Generating keys, this may take some time...");
  std::pair<CryptoPP::Integer, CryptoPP::Integer> keys =
      this->crypto_driver->EG_generate();

  // Save keys
  SaveInteger(this->arbiter_config.arbiter_secret_key_path, keys.first);
  this->cli_driver->print_left("1");
  SaveInteger(this->arbiter_config.arbiter_public_key_path, keys.second);
  this->cli_driver->print_left("2");
  LoadInteger(arbiter_config.arbiter_secret_key_path,
              this->EG_arbiter_secret_key);
  this->cli_driver->print_left("3");
  LoadInteger(arbiter_config.arbiter_public_key_path,
              this->EG_arbiter_public_key_i);
  this->cli_driver->print_left("4");
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  this->cli_driver->print_success("Keys succesfully generated and saved!");
}

/**
 * Handle partial decryption. This function:
 * 1) Updates the ElectionPublicKey to the most up to date (done for you).
 * 2) Gets all of the votes from the database.
 * 3) Verifies all of the vote ZKPs and their signatures.
 *    If a vote is invalid, simply ignore it.
 * 4) Combines all valid votes into one vote via `Election::CombineVotes`.
 * 5) Partially decrypts the combined vote.
 * 6) Publishes the decryption and zkp to the database.
 */
void ArbiterClient::HandleAdjudicate(std::string _) {
  // Ensure we have the most up-to-date election key
  LoadElectionPublicKey(common_config.arbiter_public_key_paths,
                        this->EG_arbiter_public_key);
  this->cli_driver->print_left("inside handle adjudicate");
  // Get all votes from the database
  auto all_votes = this->db_driver->all_votes();

  // Verify all vote ZKPs and their signatures
  std::vector<VoteRow> valid_votes;
  for (int i = 0; i < all_votes.size(); ++i) {
    auto current_vote = all_votes[i];
    bool vote_zkp_verified = ElectionClient::VerifyVoteZKP(std::make_pair(current_vote.vote, current_vote.zkp), this->EG_arbiter_public_key);
    if (vote_zkp_verified) {
      valid_votes.push_back(current_vote);
    }
  }
  // Combine all valid votes into one vote
  Vote_Ciphertext combined_vote = ElectionClient::CombineVotes(valid_votes);
  // Partially decrypt the combined vote
  auto [partial_decryption, decryption_zkp_struct] = ElectionClient::PartialDecrypt(combined_vote, this->EG_arbiter_public_key, this->EG_arbiter_secret_key);
  
  // Publishes the decryption and ZKP to the database
  ArbiterToWorld_PartialDecryption_Message partial_decryption_msg;
  partial_decryption_msg.dec = partial_decryption;
  partial_decryption_msg.zkp = decryption_zkp_struct;
  partial_decryption_msg.arbiter_id = this->arbiter_config.arbiter_id;
  partial_decryption_msg.arbiter_vk_path = this->arbiter_config.arbiter_public_key_path;
  PartialDecryptionRow partial_dec_row = this->db_driver->insert_partial_decryption(partial_decryption_msg);
}
