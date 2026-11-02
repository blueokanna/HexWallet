#include "WalletTotp.h"
#include "WalletUi.h"
#include <stdio.h>
#include <string.h>
static bool unlocked=true, ready=true, conflict=false, authorized=true;
static uint64_t stamp=1000000;
static char rendered[9]={};
static hexwallet::WalletUiDecisionCallback callback=nullptr;
int64_t esp_timer_get_time(){return static_cast<int64_t>(stamp*1000U);}
namespace hexwallet {
bool wallet_cli_is_authenticated(){return unlocked;}
bool wallet_cli_review_active(){return conflict;}
bool wallet_signing_active(){return false;}
bool wallet_link_service_pairing_pending(){return false;}
bool wallet_ui_ready(){return ready;}
bool wallet_ui_review_authorize(){return authorized;}
void wallet_ui_set_decision_callback(WalletUiDecisionCallback cb){callback=cb;}
void wallet_ui_show_transaction(const WalletUiTransactionReview&){}
bool wallet_ui_review_seal_code(char out[9]){memcpy(out,"12345678",9);return true;}
void wallet_ui_set_status(const char*){}
void wallet_ui_show_catalog(){memset(rendered,0,sizeof(rendered));}
bool wallet_ui_show_otp(const char*,const char*,const char *code,uint64_t){memcpy(rendered,code,9);return true;}
void wallet_ui_hide_otp(){memset(rendered,0,sizeof(rendered));}
}
using namespace hexwallet;
#define REQUIRE(x) do{if(!(x)){printf("FAIL TOTP service line=%d: %s\n",__LINE__,#x);return false;}}while(0)
bool run_totp_service_tests(){
  wallet_totp_clear();
  const char *uri="otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
  TotpAccountInfo info;
  unlocked=false;REQUIRE(!wallet_totp_import(uri,strlen(uri)));unlocked=true;
  ready=false;REQUIRE(!wallet_totp_import(uri,strlen(uri)));ready=true;
  conflict=true;REQUIRE(!wallet_totp_set_time(59));conflict=false;
  REQUIRE(wallet_totp_import(uri,strlen(uri)) && wallet_totp_pending());
  REQUIRE(!wallet_totp_info(0,&info) && !wallet_totp_set_time(59));
  callback(false);REQUIRE(!wallet_totp_pending() && !wallet_totp_info(0,&info));
  REQUIRE(wallet_totp_import(uri,strlen(uri)));authorized=false;callback(true);authorized=true;
  REQUIRE(!wallet_totp_info(0,&info));
  REQUIRE(wallet_totp_import(uri,strlen(uri)));callback(true);
  REQUIRE(wallet_totp_info(0,&info));
  REQUIRE(!wallet_totp_show(0));
  REQUIRE(wallet_totp_set_time(58));callback(true);REQUIRE(totp_clock_valid());
  REQUIRE(wallet_totp_show(0));callback(true);REQUIRE(strcmp(rendered,"94287082")==0);
  ++stamp;wallet_totp_tick();REQUIRE(rendered[0]!=0);
  stamp+=1000;wallet_totp_tick();REQUIRE(rendered[0]==0);
  REQUIRE(wallet_totp_remove(0));stamp+=120000;wallet_totp_tick();
  REQUIRE(!wallet_totp_pending() && wallet_totp_info(0,&info));
  REQUIRE(wallet_totp_remove(0));unlocked=false;callback(true);unlocked=true;
  REQUIRE(wallet_totp_info(0,&info));
  REQUIRE(wallet_totp_remove(0));callback(true);REQUIRE(!wallet_totp_info(0,&info));
  REQUIRE(wallet_totp_import(uri,strlen(uri)));wallet_totp_clear();
  REQUIRE(!wallet_totp_pending() && !wallet_totp_info(0,&info) && !totp_clock_valid());
  puts("TOTP local approval, conflict, expiry and lock lifecycle: passed");return true;
}
