#include <BaseClasses.h>
#include <Bitcoin.h>
#include <BitcoinCurve.h>
#include <Conversion.h>
#include <Hash.h>
#include <OpCodes.h>
#include <PSBT.h>
#include <uBitcoin_conf.h>
#include <string>
#include <vector>
#include <iomanip>
#include <EEPROM.h>
#include <M5Stack.h>

bool buttonA = false;
bool buttonB = false;
bool buttonC = false;
bool confirm = false;
bool loopMenu = true;
bool sdAvailable = false;

unsigned long timy;
int menuItem = 0;
String passKey;
String passHide;
String seedGenerateArr[12];
String sdCommand;
String hashed;
String savedPinHash;
String privateKey;
int warnFeePercent_ = 1;
int maxFeePercent_ = 5;
String bitcoinUnit = "sat";

String pinSet[] = {"1","2","3","4","5","6","7","8","9","0","C"};
String alphabet[] = {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","<"};
String extendedAlphabet[] = {"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"," ","'"};

//******************************************************
//Function prototypes
void pinMaker();
void showSeed();
bool enterPin(bool set);
void redrawPin(int index, int hidePin);
void restoreFromSeed(String theSeed);
void wipeSD();
String getValue(String data, char separator, int index);
void enterDangerZone();
std::vector<String> indexAccounts();
void writeFile(fs::FS &fs, const char *path, const char *message);
void getKeys(String mnemonic, String password);
String getValue(String data, char separator, int index);
void writeIntIntoEEPROM(int addresss, int number);
void exportMaster();
void exportAddresses();
void signPSBT();
void Receive();
void seedMaker();
void readFile(fs::FS &fs, const char *path);
String inputWords(int numOfWords);
bool testMnemonic();
int mod(int a, int n);
void showReceiveHelp();
void showZpubHelp();
void settingsMenu(int menuCounter);
void advancedMenu(int menuCounter);
void printAdvancedMenu();
std::vector<String> getAccountNames(std::vector<String> accounts);
void displayLoadingBar(int percent);
String inputMnemonic();
void drawTestMnemonic(int word);
void printSettingsMenu(int menuCounter);
void printAddress(String freshPub);
void sdChecker();
bool isPSBT(const char* filename);
const char* locatePSBT(File dir, int numTabs);
String b64_encode(String str);
void printTx(PSBT psbt);
bool confirmSign(PSBT psbt);
void printSignedTx();
bool isFeeTooHigh(float fee, float amount);
void drawIncorrectPin();
void drawCorrectPin(uint16_t color);
void showPrompt(String message);
String bip38Setup();
void displayMnemonicWords(String seedGenerateStr);
void deleteAddedData(fs::FS &fs, const char* path);
void changeGapLimit();
void printGapLimit(bool set, int gapLimit);
void setMaxFee();
void exportWallet();
void printExportWalletMenu(int &menuCounter, std::vector<String> accountNames, int accountIDSelected);
int getAccountId(String accountStr);
String getAccountName(String accountStr);

//*******************************************************

class Account {

private:

  String accountName_;
  String xpub_;
  HDPublicKey zpub_;
  String derivationPath_;
  HDPrivateKey accountPrivateKey_;
  int accountID_;
  int gapLimit_ = 20;

  void getKeys() {

    File otherFile = SD.open("/key.txt");
    privateKey = otherFile.readStringUntil('\n');
    otherFile.close();
    char* result = strcpy((char*)malloc(privateKey.length()+1), privateKey.c_str());
    HDPrivateKey root(result);

    if (!root)
    { // check if it is valid
      return;
    }
    HDPrivateKey accountPrivateKey = root.derive(derivationPath_);
    accountPrivateKey_ = accountPrivateKey; //change this!!
    zpub_ = accountPrivateKey.xpub();
    HDPrivateKey privKey = root.derive("m/84'/");
    xpub_ = privKey.xpub();
    Serial.println(xpub_);
  }

  public:
    Account() {
      //empty constructor
    }

    Account(String accountName, String derivationPath) {
      accountName_ = accountName;
      derivationPath_ = derivationPath;
      getKeys();
    }

    //***********************************************************

    void Receive() {
      sdChecker();
      HDPublicKey hd(zpub_);
      String filePath = "/account.txt";
      File rFile = SD.open(filePath);
      String accounts = rFile.readStringUntil(EOF);
      rFile.close();
      String pubNumStr = "";
      int accountIndex = accounts.indexOf(accountName_);
      while(accounts[accountIndex] != '/') {
        accountIndex++;
      }
      String pre = accounts.substring(0, accountIndex + 1);
      while(accounts[accountIndex] != '\n') {
        accountIndex++;
        pubNumStr += accounts[accountIndex];
      }
      String post = accounts.substring(accountIndex, accounts.length() + 1);
      int pubNum = pubNumStr.toInt();
      int nextPubNum = pubNum + 1;
      Serial.println("using num " + pubNumStr);
      String newAccounts = pre + nextPubNum + post;
      Serial.println(newAccounts);

      File wFile = SD.open(filePath, FILE_WRITE);
      wFile.print(newAccounts);
      wFile.close();

      HDPublicKey pub = zpub_.child(0).child(pubNum);
      String freshPub = pub.address();
      printAddress(freshPub);
      M5.update();
      while (M5.BtnB.wasReleased() == false) {
        if (M5.BtnB.wasReleased()) {
          return;
        }
        else if(M5.BtnA.wasReleased()) {
          showReceiveHelp();
          printAddress(freshPub);
        }
        M5.update();
        if(M5.BtnC.wasReleased()) {
          //save to sd
          sdChecker();
          if (sdAvailable) {
            writeFile(SD, "/address.txt", freshPub.c_str());
            M5.Lcd.setCursor(160, 180);
            M5.Lcd.setTextColor(GREEN);
            M5.Lcd.println(" Saved to SD!");
          }
          else {
            M5.Lcd.setCursor(150, 180);
            M5.Lcd.setTextColor(RED);
            M5.Lcd.println(" No SD!");
          }
        }
      }
    }

    //*************************************************************

    void signPSBT() {
      File root = SD.open("/");
      const char* psbtFilename = locatePSBT(root, 0);
      File psbtFile = SD.open(psbtFilename);
      if(!psbtFile) Serial.println("Couldnt read file");
      int size = psbtFile.size();
      byte *psbtStr = new byte[size];
      psbtFile.read(psbtStr, size);
      //TODO: validate length of file
      psbtFile.close();
      String hexStr = "";
      String s;
      for(int i = 0; i < size; i++) {
        s = String((int)psbtStr[i], HEX);
        if (s.length() == 1) {
          s = "0" + s;
        }
        hexStr += s;
      }
      String b64Psbt = b64_encode(hexStr);
      PSBT psbt;
      psbt.parseBase64(b64Psbt);
      printTx(psbt);
    }

    //****************************************************************

    void printTx(PSBT psbt) {
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setTextSize(2.5);
      M5.Lcd.setTextColor(0x3a59);
      M5.Lcd.setCursor(0,10);
      M5.Lcd.println("    Review transaction");
      M5.Lcd.setCursor(0,50);
      M5.Lcd.setTextSize(2);
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println("Address:");
      // going through all outputs
      for(int i=0; i<psbt.tx.outputsNumber; i++){

      }
      String recipient = psbt.tx.txOuts[0].address(&Mainnet);
      for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 14; j++) {
          int index = 14 * i + j;
          if(i == 1) {
            M5.Lcd.setTextColor(0x3a59);
          }
          else {
            M5.Lcd.setTextColor(WHITE);
          }
          M5.Lcd.print(recipient[index]);
        }
        M5.Lcd.println();
      }
      M5.Lcd.println();
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.print("Amount: ");

      int amount = psbt.tx.txOuts[0].amount;
        M5.Lcd.println((String)amount + " sats");
        M5.Lcd.println();
        M5.Lcd.print("Fee: ");
      int fee = psbt.fee();
        M5.Lcd.println((String)fee + " sats");

      M5.Lcd.setCursor(0,220);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.println("   <Back           Sign>");

      bool aboveMaxFee = isFeeTooHigh(fee, amount);

      M5.update();
      while (M5.BtnC.wasReleased() == false) {
        M5.update();
        if(M5.BtnC.wasReleased()) {
          Serial.println("Sign");
          if(confirmSign(psbt) == false || aboveMaxFee) {
            printTx(psbt);
          }
          else {
            printSignedTx();
            delay(2000);
          }
        }
        else if(M5.BtnA.wasReleased()) {
          break;
        }
      }
      loop(); //return to home
    }

    //*******************************************************

    bool confirmSign(PSBT psbt) {
      showPrompt("Sign Transaction?");
      M5.update();
      while(M5.BtnC.wasReleased() == false) {
        M5.update();
        if(M5.BtnC.wasReleased()) {
          psbt.sign(accountPrivateKey_);
          return true;
        }
        else if(M5.BtnA.wasReleased()) {
          return false;
        }
      }
    }

    //********************************************************************

    void exportAddresses() {
      String csv = "Index\",\"Payment Address\",\"Derivation";
      HDPublicKey pub;
      String addr;
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setCursor(10, 100);
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println(" Exporting Addresses..");
      M5.Lcd.setCursor(10, 200);
      M5.Lcd.setTextColor(YELLOW);
      M5.Lcd.println("Saving to bip84_addresses.txt on the SD card");
      for(int i = 0; i < 250; i++) {
        int percent = round((i/250.0) * 100);
        displayLoadingBar(percent);
        pub = zpub_.child(0).child(i);
        addr = pub.address();
        csv += (String)i + ",\"" + addr + "\"," + derivationPath_ + (String)i + '\n';
      }
      File file = SD.open("/bip84_addresses.txt", FILE_WRITE);
      file.print(csv);
      file.close();
    }

    //******************************************************************

    String getAccountName() {
      return accountName_;
    }

    String getZpub() {
      return zpub_;
    }

    String getDerivationPath() {
      return derivationPath_;
    }

    int getAccountID() {
      return accountID_;
    }

    int getGapLimit() {
      return gapLimit_;
    }

    void setGapLimit(int gapLmt) {
      if(gapLmt > 0) {
        gapLimit_ = gapLmt;
      }
    }
};

Account createNewAccount();
Account selectAccount();
bool createGenericWallet(Account account);
Account account_;

//====================================================================

void GapLimitHelpMenu() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setCursor(10,10);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("     Help");
  M5.Lcd.println();
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("When restoring a HD wallet");
  M5.Lcd.println("the gap limit is the");
  M5.Lcd.println("interval between addresses");
  M5.Lcd.println("it checks for funds.");
  M5.Lcd.println("increasing this may be");
  M5.Lcd.println("helpful if your previous");
  M5.Lcd.println("wallet generated many");
  M5.Lcd.println("empty addresses. Otherwise");
  M5.Lcd.println("you may not see your funds");
  M5.Lcd.setCursor(30, 210);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("<Back");
  M5.update();
  while(M5.BtnA.wasReleased() == false) {
    M5.update();
    delay(10);
    if(M5.BtnA.wasReleased()) {
      Serial.println("A");
      return;
    }
  }
}

//=======================================================================

void printGapLimit(bool set, int gapLimit) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.setCursor(0,10);
  M5.Lcd.println("Change Gap Limit");
  M5.Lcd.println();
  M5.Lcd.setTextSize(2);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("Set gap size (default 20)");
  if(!set) {
    M5.Lcd.setTextColor(YELLOW, 0x3a59);
    M5.Lcd.println(gapLimit);
    M5.Lcd.setCursor(58, 210);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.setTextSize(3);
    M5.Lcd.print("-");
    //put a tick image in the centre
    M5.Lcd.setCursor(248, 210);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print("+");
  }
  else {
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(gapLimit);
    M5.Lcd.setCursor(40, 210);
    M5.Lcd.print("Help");
    M5.Lcd.setCursor(135, 210);
    M5.Lcd.setTextColor(0x3a59);
    M5.Lcd.print("Home");
    M5.Lcd.setCursor(230, 210);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print("Save");
  }
  M5.Lcd.setCursor(0, 110);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("This will tell your wallet");
  M5.Lcd.println("to skip intervals of this");
  M5.Lcd.println("value when checking for");
  M5.Lcd.println("bitcoin in the address");
}

//=====================================================================

void changeGapLimit() {
  int gapLimit = account_.getGapLimit();
  bool set = false;
  printGapLimit(set, gapLimit);
  M5.update();
  while(!set) {
    delay(10);
    M5.update();
    if(M5.BtnB.wasReleased()) {
      set = true;
    }
    else if(M5.BtnA.wasReleased()) {
      if(gapLimit - 1 > 0) {
        gapLimit--;
      }
      printGapLimit(set, gapLimit);
    }
    else if(M5.BtnC.wasReleased()) {
      gapLimit++;
      printGapLimit(set, gapLimit);
    }
  }
  printGapLimit(set, gapLimit);
  M5.update();
  bool saved = false;
  while(!saved) {
    M5.update();
    delay(10);
    if(M5.BtnA.wasReleased()) { //help
      GapLimitHelpMenu();
      printGapLimit(set, gapLimit);
    }
    else if(M5.BtnB.wasReleased()) {
      break;
    }
    else if(M5.BtnC.wasReleased()) {
      account_.setGapLimit(gapLimit);
      saved = true;
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.setCursor(45, 110);
      M5.Lcd.setTextSize(2);
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.println("Gap limit saved!");
      delay(2000);
    }
  }
}

//=====================================================================

void sdChecker() {
  readFile(SD, "/key.txt");
  readFile(SD, "/account.txt");
}

//========================================================

int mod(int a, int n) {
  int result = a % n;
  if ((result < 0 && n > 0) || (result > 0 && n < 0))
  {
      result += n;
  }
  return result;
}

//===================================================================

void printAddress(String freshPub) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 10);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.println(" BITCOIN ADDRESS");
  M5.Lcd.setCursor(0, 46);
  M5.Lcd.qrcode(freshPub, 5, 46, 160, 3);
  M5.Lcd.setTextSize(2);
  int i = 0;
  while (i < freshPub.length() + 1) {
    M5.Lcd.println("              " + freshPub.substring(i, i + 12));
    i = i + 12;
  }

  M5.Lcd.setCursor(40,220);
  M5.Lcd.println("Help    Home    Save");
}

//=======================================================

void printSignedTx() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(20,50);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Transaction signed");
}

//========================================================

bool isFeeTooHigh(float fee, float amount) {
  int percent = (fee / amount) * 100;
  if(percent > maxFeePercent_) {
    M5.Lcd.setTextSize(1);
    M5.Lcd.drawRoundRect(180, 63, 115, 50, 4, RED);
    M5.Lcd.setCursor(195, 75);
    M5.Lcd.println("Fee higher than");
    M5.Lcd.setCursor(195, 85);
    M5.Lcd.println("max fee limit");
    M5.Lcd.setTextSize(2);
    return true;
  }
  else if(percent > warnFeePercent_ && percent < maxFeePercent_) {
    M5.Lcd.setTextSize(1);
    M5.Lcd.drawRoundRect(180, 63, 115, 50, 4, ORANGE);
    M5.Lcd.setCursor(195, 75);
    M5.Lcd.println("Warning: fee");
    M5.Lcd.setCursor(195, 85);
    M5.Lcd.println("Exceeds " + (String)warnFeePercent_ + "% of");
    M5.Lcd.setCursor(195, 95);
    M5.Lcd.println("transaction.");
    M5.Lcd.setTextSize(2);
  }
  return false;
}

//==========================================================

void showPrompt(String message) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 100);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.println(message);
  M5.Lcd.setCursor(20, 200);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("  No       Yes");
}

//===========================================================

String b64_encode(String str) {
      String newStr = "";
      String ref = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

      //Number of bytes per 12 bits
      int bytes = str.length() / 3;
      int padding = str.length() % 3;

      //Padding must be either 0 or 1
      if(padding > 2)
      {
          return newStr;
      }

      //Number of characters to be encoded is 3

      int count = bytes * 3;

      unsigned long long h = 0;

      int i = 0;
      for(i=0; i<count; i+=3) //iterate every 3 chars
      {
          //Get every 3 chars
          char a[2] = {str[i], 0};
          char b[2] = {str[i+1], 0};
          char c[2] = {str[i+2], 0};

          //Now, convert each hex character (base 16) to it's equivalent decimal number
          //and merge them into one variable
          h = strtoull(a, nullptr, 16) << 8; //shift left by 8 bits
          h |= strtoull(b, nullptr, 16) << 4; //shift left by 4 bits
          h |= strtoull(c, nullptr, 16); //no shift required only the first 2 characters need

          //HEX: 0x3F -> DEC: 63 -> ASCII: ?

          newStr += ref[0x3F & (h >> 6)]; //first b64 char; shift to right by 6 bits
          newStr += ref[0x3F & h]; //second b64 char
      }

      //if padding is required
      //Follows the same pattern as the above.
      if(padding == 1)
      {
          char a[2] = {str[i], 0};
          h = strtoull(a, nullptr, 16) << 8; // shift left by 8 bits
          newStr += ref[0x3F & (h >> 6)];
          newStr += '='; //add this towards the end of the encoded string
      }
      return newStr;
    }

//===========================================================

void showReceiveHelp() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(125, 10);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Help");
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(0,60);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.println("Send bitcoin by scanning");
  M5.Lcd.println("the qr code or copying the");
  M5.Lcd.println("address. Addresses can be");
  M5.Lcd.println("found in address.txt on");
  M5.Lcd.println("the SD card.");
  M5.Lcd.setCursor(30, 220);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("Return");
  M5.Lcd.setTextColor(0x3a59);
  M5.update();
  while(M5.BtnA.wasReleased() == false) {
    delay(100);
    M5.update();
  }
}

//==============================================================

void showZpubHelp() {
  M5.Lcd.setTextColor(RED);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(125, 10);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Help");
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(0,60);
  M5.Lcd.println("The Extended public key");
  M5.Lcd.println("can be used to generate");
  M5.Lcd.println("all addresses in an");
  M5.Lcd.println("account and can be ");
  M5.Lcd.println("exported to the SD card.");
  M5.Lcd.setCursor(30, 220);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("Return");
  M5.Lcd.setTextColor(0x3a59);
  M5.update();
  while(M5.BtnA.wasReleased() == false) {
    delay(100);
    M5.update();
  }
}

//=======================================================

void printZpub(String zpub) {
  M5.Lcd.setTextColor(RED);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 10);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("   EXPORT ZPUB");
  M5.Lcd.qrcode(zpub, 5, 46, 160);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(0, 46);
  int i = 0;
  while (i < zpub.length() + 1)
  {
    M5.Lcd.println("              " + zpub.substring(i, i + 12));
    i = i + 12;
  }
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(40,220);
  M5.Lcd.println("Help    Home    Save");
}

//=======================================================

void exportMaster() {
  sdChecker();
  if (sdAvailable) {
    String zpub = account_.getZpub();
    int str_len = zpub.length() + 1;
    char char_array[str_len];
    zpub.toCharArray(char_array, str_len);
    printZpub(zpub);
    while (M5.BtnB.wasReleased() == false) {
      if (M5.BtnB.wasReleased()) {
        return; //return home
      }
      else if(M5.BtnA.wasReleased()) {
        showZpubHelp();
        printZpub(zpub);
      }
      else if(M5.BtnC.wasReleased()) { //save to sd
        File xpubFile = SD.open("/zpub.txt", FILE_WRITE);
        xpubFile.print(char_array);
        xpubFile.close();
        M5.Lcd.setCursor(160, 180);
        M5.Lcd.setTextColor(GREEN);
        M5.Lcd.println(" Saved to SD!");

      }
      M5.update();
    }
    buttonC = false;
    sdCommand = "";
  }
  else {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 100);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println("    No SD Available");
    delay(2000);
    M5.Lcd.setTextColor(0x3a59);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setCursor(0, 220);
    M5.Lcd.println("    Press C for menu");
  }
}

//==========================================================================

void printSelectWord(std::vector<String> shortlist, int wordIndex) {
  int size = shortlist.size();
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(50, 10);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Select Word");
  M5.Lcd.setCursor(0, 50);
  for(int i = 0; i < size; i++) {
    if(i == wordIndex) {
      M5.Lcd.setTextColor(WHITE, 0x3a59);
      M5.Lcd.println(shortlist[i]);
    }
    else {
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println(shortlist[i]);
    }
  }
}

//==========================================================================

String selectWord(std::vector<String> shortlist) {
  int size = shortlist.size();
  String chosenWord = "";
  int wordIndex = 0;
  printSelectWord(shortlist, wordIndex);
  M5.update();
  while(M5.BtnB.wasReleased() == false) {
    M5.update();
    if(M5.BtnB.wasReleased()) {
      chosenWord = shortlist[wordIndex];
      return chosenWord;
    }
    if(M5.BtnA.wasReleased()) {
      wordIndex = mod(wordIndex - 1, size);
      printSelectWord(shortlist, wordIndex);
    }
    if(M5.BtnC.wasReleased()) {
      wordIndex = mod(wordIndex + 1, size);
      printSelectWord(shortlist, wordIndex);
    }
  }
}

//=========================================================================

std::vector<String> findMatchingWords(String target) {
  std::vector<String> matchingList = std::vector<String>();
  bool getline = false;
  File keyFile = SD.open("/bip39_english.txt");
  String words = keyFile.readStringUntil(EOF);
  keyFile.close();
  String curr = "";
  for(char letter : words) {
    if(letter == '\n' && getline == false) {
      curr = "";
    }
    else if(letter == '\n' && getline) {
      if(letter == '\n') {
        matchingList.push_back(curr);
        curr = "";
        getline = false;
      }
    }
    else {
      curr = curr + letter;
      if(curr.length() == target.length()) {
        if(curr == target) {
          getline = true;
        }
      }
    }
  }
  return matchingList;
}

//==========================================================================

void drawTestMnemonic(int wordNum) {
  M5.Lcd.setTextSize(2);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(RED);
  M5.Lcd.setCursor(10, 50);
  M5.Lcd.println("Enter word #" + (String)wordNum);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.setCursor(10, 180);
  M5.Lcd.println("  Press home to exit");
  M5.Lcd.setTextColor(RED);
  M5.Lcd.setCursor(10, 100);
}

//==========================================================================

String inputMnemonic(int length = 12) {
  std::vector<String> possibleWords = std::vector<String>();
  bool found = false;
  int alphaIndex = 0;
  String currWord = "";
  String currLetter = "a";
  String mnemonic = "";
  for(int i = 1; i <= length; i++) {
    found = false;
    int alphaIndex = 0;
    drawTestMnemonic(i);
    alphaIndex = mod(alphaIndex, 27);
    currLetter = alphabet[alphaIndex];
    M5.Lcd.setTextColor(WHITE);
    M5.Lcd.print(currWord + currLetter);
    M5.Lcd.setTextColor(RED);
    M5.update();
    while(found == false) {

      if(M5.BtnA.wasPressed()) {
        buttonA = true;
      }
      if(M5.BtnC.wasPressed()) {
        buttonC = true;
      }
      if(M5.BtnC.wasReleased() && (buttonA && buttonC)) {
        buttonA = false;
        buttonC = false;
        if(currLetter == "<") {
          currLetter = currWord[currWord.length() - 1];
          currWord.remove(currWord.length() - 1);
          alphaIndex = 0;
          drawTestMnemonic(i);
          M5.Lcd.print(currWord);
          M5.Lcd.setTextColor(WHITE);
          M5.Lcd.print(currLetter);
          M5.Lcd.setTextColor(RED);
        }
        else {
          currWord = currWord + alphabet[alphaIndex];
          drawTestMnemonic(i);
          alphaIndex = 0;
          currLetter = alphabet[alphaIndex];
          M5.Lcd.print(currWord);
          M5.Lcd.setTextColor(WHITE);
          M5.Lcd.print(currLetter);
          M5.Lcd.setTextColor(RED);
          possibleWords = findMatchingWords(currWord);
          if(possibleWords.size() <= 5 && !possibleWords.empty()) {
            currWord = "";
            /*FIXME! concat writes over the string*/
            String nextWord = selectWord(possibleWords);
            nextWord.trim();
            mnemonic += " " + nextWord;
            found = true;
          }
          else if (possibleWords.empty()) {
            M5.Lcd.fillScreen(BLACK);
            M5.Lcd.setTextColor(RED);
            M5.Lcd.setCursor(10, 100);
            M5.Lcd.println("Couldn't find matching words");
            delay(3000);
            drawTestMnemonic(i);
            currLetter = currWord[currWord.length() - 1];
            currWord.remove(currWord.length() - 1);
            M5.Lcd.print(currWord);
            M5.Lcd.setTextColor(WHITE);
            M5.Lcd.print(currLetter);
            M5.Lcd.setTextColor(RED);
          }
        }

      }
      else if(M5.BtnA.wasReleased() && !buttonC) {
        buttonA = false;
        drawTestMnemonic(i);
        alphaIndex = mod(alphaIndex - 1, 27);
        currLetter = alphabet[alphaIndex];
        M5.Lcd.print(currWord);
        M5.Lcd.setTextColor(WHITE);
        M5.Lcd.print(currLetter);
        M5.Lcd.setTextColor(RED);
      }
      else if(M5.BtnC.wasReleased() && !buttonA) {
        buttonC = false;
        drawTestMnemonic(i);
        alphaIndex = mod(alphaIndex + 1, 27);
        currLetter = alphabet[alphaIndex];
        M5.Lcd.print(currWord);
        M5.Lcd.setTextColor(WHITE);
        M5.Lcd.print(currLetter);
        M5.Lcd.setTextColor(RED);
      }
      else if(M5.BtnB.wasReleased()) {
        showPrompt("Exit to home?");
        while(M5.BtnA.wasReleased() == false && M5.BtnC.wasReleased() ==false) {
          M5.update();
          if(M5.BtnC.wasReleased()) {
            return ""; //exit to loop
          }
        }
        drawTestMnemonic(i);
        alphaIndex = mod(alphaIndex, 27);
        currLetter = alphabet[alphaIndex];
        M5.Lcd.setTextColor(WHITE);
        M5.Lcd.print(currWord + currLetter);
        M5.Lcd.setTextColor(RED);
      }
      M5.update();
    }
  }
  mnemonic.trim();
  return mnemonic;
}

//===========================================================================

bool testMnemonic() {

  String mnemonic = inputMnemonic(12);
  if(mnemonic == "") {
    return false;
  }
  Serial.println(mnemonic);
  String pass = "";
  File otherFile = SD.open("/key.txt");
  String key = otherFile.readStringUntil('\n');
  otherFile.close();
  char* result = strcpy((char*)malloc(key.length()+1), key.c_str());

  HDPrivateKey root(result);
  HDPrivateKey userGeneratedKey(mnemonic, pass);

  if(root == userGeneratedKey) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.setTextSize(3);
    M5.Lcd.println("Key is correct");
    delay(3000);
    return true;
  }
  else {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.setCursor(10,10);
    M5.Lcd.setTextSize(3);
    M5.Lcd.println("Key is incorrect");
    M5.Lcd.setCursor(10, 100);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.setTextSize(2);
    M5.Lcd.println("   Make sure you typed");
    M5.Lcd.println("   your key in correctly!");
    delay(2000);
    testMnemonic();
  }
  return true;
}

//===========================================================================

void wipeDevice() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 20);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.println("RESET/WIPE DEVICE");
  M5.Lcd.setCursor(0, 90);
  M5.Lcd.setTextColor(RED);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Device will be reset,");
  M5.Lcd.println("are you sure?");
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(0, 220);
  M5.Lcd.println("A to continue, C to cancel");

  while (buttonA == false && buttonC == false) {
    if (M5.BtnA.wasReleased()) {
      buttonA = true;
    }
    if (M5.BtnC.wasReleased()) {
      buttonC = true;
    }
    M5.update();
  }
  if (buttonA == true) {
    wipeSD();
    seedMaker();
    pinMaker();
  }

  buttonA = false;
  buttonC = false;
}

//===============================================================

void seedChecker() {
  File otherFile = SD.open("/key.txt");
  privateKey = otherFile.readStringUntil('\n');
  otherFile.close();
  int seedCount = 0;

  for (int x = 0; x < 12; x++) {
    for (int z = 0; z < 2048; z++) {
      if (getValue(privateKey, ' ', x) == seedGenerateArr[z]) {
        seedCount = seedCount + 1;
      }
    }
  }

  if (int(seedCount) != 12) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 90);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.setTextSize(2);
    M5.Lcd.println("   Error: Reset device");
    M5.Lcd.println("   or restore from seed");
    M5.Lcd.println("   (See documentation)");
    delay(99999999);
  }
  else
  {
    return;
  }
}

//=====================================================================

void seedMaker() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 100);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Write words somewhere safe");
  delay(5000);
  buttonA = false;

  uint8_t arr[32];
  for (int i = 0; i < sizeof(arr); i++) {
    arr[i] = esp_random() % 256;
  }
  String seedGenerateStr = generateMnemonic(12, arr, sizeof(arr));

  displayMnemonicWords(seedGenerateStr);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 100);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println(" Time to check the words!");
  delay(3000);
  displayMnemonicWords(seedGenerateStr);

  M5.Lcd.fillScreen(BLACK);
  String bip38Passphrase = bip38Setup();

  String phrase = seedGenerateStr.substring(0, seedGenerateStr.length());
  HDPrivateKey root(phrase, bip38Passphrase);
  String privateK = root;
  File file = SD.open("/key.txt", FILE_WRITE);
  file.print(privateK + '\n');
  file.close();
}

//========================================================================

void displayMnemonicWords(String seedGenerateStr) {
  for (int z = 0; z < 12; z++) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 70);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println("   Word " + String(z + 1));
    M5.Lcd.println("");
    M5.Lcd.setTextSize(5);
    M5.Lcd.setTextColor(BLUE);
    M5.Lcd.println(" " + getValue(seedGenerateStr, ' ', z));
    M5.Lcd.setTextSize(2);
    M5.Lcd.println("");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.setCursor(195,210);
    M5.Lcd.println("next word>");

    while (buttonC == false) {
      if (M5.BtnC.wasReleased()) {
        buttonC = true;
      }
      M5.update();
    }
    buttonC = false;
  }
}

//=========================================================================

String bip38Setup() {

  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Would you like to");
  M5.Lcd.println("set a passphrase");
  M5.Lcd.println("to encrypt your");
  M5.Lcd.println("key?");
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println();
  M5.Lcd.println("What is this?");
  M5.Lcd.println("If your mnemonic is");
  M5.Lcd.println("compromised, the attacker");
  M5.Lcd.println("won't be able to take");
  M5.Lcd.println("your funds without the");
  M5.Lcd.println("passphrase. However, you");
  M5.Lcd.fillTriangle(147, 215, 157, 230, 167, 215, WHITE);
  M5.update();
  while(M5.BtnB.wasReleased() == false) {
    delay(10);
    M5.update();
  }
  M5.Lcd.clear();
  M5.Lcd.setCursor(0,0);
  M5.Lcd.println("cannot restore your wallet");
  M5.Lcd.println("if you lose it!");
  M5.Lcd.println("This should be backed up");
  M5.Lcd.println("on paper seperately from");
  M5.Lcd.println("your mnemonic phrase.");
  M5.Lcd.fillTriangle(147, 230, 157, 215, 167, 230, WHITE);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setCursor(50, 130);
  M5.Lcd.println("Setup passphrase?");
  M5.Lcd.setCursor(50, 220);
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("No             Yes");
  M5.update();
  while(M5.BtnC.wasReleased() == false && M5.BtnA.wasReleased() == false) {
    delay(10);
    M5.update();
    if(M5.BtnA.wasReleased()) {
      return ""; //empty passphrase
    }
    if(M5.BtnC.wasReleased()) {
      String passphrase = inputWords(1);
      return passphrase;
    }
  }
}

//=========================================================================

void pinMaker() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 90);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("Choose pin with 8 characters");
  delay(6000);
  enterPin(true);
}

//========================================================================

bool enterPin(bool set) {

    passKey = "";
    int hidePin = 0;
    int index;
    bool correct = false;
    index = esp_random() % 10;
    String curr = pinSet[index];

   M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setTextColor(WHITE);
    M5.Lcd.setCursor(0, 10);
    M5.Lcd.setTextSize(3);
    redrawPin(index, hidePin);

    while (correct == false) {

      if(M5.BtnA.wasPressed()) {
        buttonA = true;
      }
      if(M5.BtnC.wasPressed()) {
        buttonC = true;
      }

      if (M5.BtnA.wasReleased() && !buttonC){
        buttonA = false;
        index = mod((index - 1), 11);
        curr = pinSet[index];
        redrawPin(index, hidePin);
      }
      else if (M5.BtnC.wasReleased() && !buttonA){
        buttonC = false;
        index = mod((index + 1), 11);
        curr = pinSet[index];
        redrawPin(index, hidePin);
     }
      else if (M5.BtnC.wasReleased() && (buttonA && buttonC)){ //double press
        buttonA = false;
        buttonC = false;
        curr = pinSet[index];
        if(curr == "C") {
          passKey = passKey.substring(0, passKey.length() - 1);
          hidePin--;
          redrawPin(index, hidePin);
        }
        else {
        hidePin++;
        passKey += curr;
        index = esp_random() % 10;
        if (set){
          uint8_t newPassKeyResult[32];
          sha256(passKey, newPassKeyResult);
          hashed = toHex(newPassKeyResult, 32);

          File file = SD.open("/pass.txt", FILE_WRITE);
          file.print(hashed + "\n");
          file.close();
        }

        if(passKey.length() == 8) {
          File otherFile = SD.open("/pass.txt");
          savedPinHash = otherFile.readStringUntil('\n');
          otherFile.close();

          uint8_t passKeyResult[32];
          sha256(passKey, passKeyResult);
          hashed = toHex(passKeyResult, 32);
          if (savedPinHash == hashed || set == true) {
            correct = true;
            redrawPin(index, hidePin);
            drawCorrectPin(GREEN);
            drawCorrectPin(WHITE);
            drawCorrectPin(GREEN);
            drawCorrectPin(WHITE);
            return correct;
          }
          else if (savedPinHash != hashed && set == false){ //incorrect pin
            passKey = "";
            hidePin++;
            drawIncorrectPin();
            hidePin = 0;
            curr = pinSet[index];
          }
        }
        else {
          redrawPin(index, hidePin);
        }
      }
    }
    M5.update();
  }
  enterPin(false);
  return correct;
}

//========================================================================

void redrawPin(int index, int hidePin) {
      int length = 11;
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setTextColor(BLUE);
      M5.Lcd.setCursor(0,10);
      M5.Lcd.setTextSize(4);
      M5.Lcd.println(" Enter pin: ");
      int x = 5;
      for(int i = 0; i < 8; i++) {
        if(i == hidePin) {
          M5.Lcd.drawRoundRect(x, 95, 30, 50, 4, WHITE);
        }
        else {
          M5.Lcd.drawRoundRect(x, 95, 30, 50, 4, 0x07ff);
        }
        x += 40;
      }
      x = 19;
      for(int i = 0; i < hidePin; i++) {
        M5.Lcd.fillCircle(x, 118, 10, WHITE);
        x += 40;
      }
      M5.Lcd.setTextColor(0x3a59);
      M5.Lcd.setCursor(hidePin * 40 + 10, 105);
      if(hidePin < 8) {
        M5.Lcd.print(pinSet[mod(index, length)]);
      }
}

//========================================================================

void drawIncorrectPin() {
  int x = 5;
  int y = 95;
  for(int i = 0; i < 8; i++) {
    M5.Lcd.fillRoundRect(x, y, 30, 50, 4, BLACK);
    M5.Lcd.drawRoundRect(x, y, 30, 50, 4, RED);
    x += 40;
    delay(40);
  }
  M5.Lcd.setCursor(10, 175);
  M5.Lcd.setTextColor(RED);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Wrong pin, try again");
}

//========================================================================

void drawCorrectPin(uint16_t color) {
  int x = 5;
  int y = 95;

  for(int i = 0; i < 8; i++) {
    M5.Lcd.drawRoundRect(x, y, 30, 50, 4, color);
    x += 40;
  }
  delay(150);
}

//=========================================================================

void restoreFromSeed(String theSeed) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 20);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("RESTORE FROM SEED");
  M5.Lcd.setCursor(0, 85);
  M5.Lcd.setTextColor(RED);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Device will be wiped");
  M5.Lcd.println("then restored from seed");
  M5.Lcd.println("are you sure?");
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(0, 220);
  M5.Lcd.println("A to continue, C to cancel");

  while (buttonA == false && buttonC == false)
  {
    if (M5.BtnA.wasReleased()) {
      buttonA = true;
    }
    if (M5.BtnC.wasReleased()) {
      buttonC = true;
    }
    M5.update();
  }
  if (buttonA == true) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 100);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.setTextSize(2);
    M5.Lcd.println("     Saving seed...");
    delay(2000);
    File file = SD.open("/key.txt", FILE_WRITE);
    file.print(theSeed + "\n");
    file.close();
    File otherFile = SD.open("/key.txt");
    privateKey = otherFile.readStringUntil('\n');
    otherFile.close();
  }

  buttonA = false;
  buttonC = false;
}

//========================================================================

void wipeSD() {
  //File root = SD.open("/");
  //deleteAddedData(root, 0);
deleteAddedData(SD, "/key.txt");
deleteAddedData(SD, "/account.txt");
deleteAddedData(SD, "/zpub.txt");
deleteAddedData(SD, "/address.txt");
deleteAddedData(SD, "/pass.txt");
deleteAddedData(SD, "/bip84_addresses.txt");

}

//========================================================================

void deleteAddedData(fs::FS &fs, const char* path) {
  File f = fs.open(path, FILE_WRITE);
  if(!f) {
    Serial.println("No file found!");
    return;
  }
  else {
    f.print('\n');
    f.close();
  }
}

//========================================================================

String getValue(String data, char separator, int index) {
  int found = 0;
  int strIndex[] = {0, -1};
  int maxIndex = data.length() - 1;

  for (int i = 0; i <= maxIndex && found <= index; i++)
  {
    if (data.charAt(i) == separator || i == maxIndex)
    {
      found++;
      strIndex[0] = strIndex[1] + 1;
      strIndex[1] = (i == maxIndex) ? i + 1 : i;
    }
  }

  return found > index ? data.substring(strIndex[0], strIndex[1]) : "";
}

//========================================================================

void readFile(fs::FS &fs, const char *path) {
  File file = fs.open(path);
  if (!file)
  {
    sdAvailable = false;
    return;
  }
  sdAvailable = true;
  while (file.available())
  {
    sdCommand = file.readStringUntil('\n');
  }
}

//========================================================================

const char* locatePSBT(File dir, int numTabs) {
  while(true) {
    File entry =  dir.openNextFile();
    if (! entry) {
      // no more files
      break;
    }
    if ( isPSBT(entry.name())) { // Here is the magic
      return entry.name();
    }

    if (entry.isDirectory()) { // Dir's will print regardless, you may want to exclude these
      locatePSBT(entry, numTabs + 1);
    }
    entry.close();
  }
}

//=======================================================================

bool isPSBT(const char* filename) {
  int8_t len = strlen(filename);
  bool result;
  if (  strstr(strlwr((char*)filename + (len - 5)), ".psbt")) {
    result = true;
  } else {
    result = false;
  }
  return result;
}

//=======================================================================

void writeFile(fs::FS &fs, const char *path, const char *message) {

  File file = fs.open(path, FILE_WRITE);
  if (!file)
  {
    M5.Lcd.println("Failed to open file for writing");
    return;
  }
  if (file.print(message))
  {
  }
  else
  {
    M5.Lcd.println("   Write failed");
  }
}

//========================================================================

void writeIntIntoEEPROM(int addresss, int number) {
  EEPROM.write(addresss, number);
}

//=========================================================================

int readIntFromEEPROM(int addresss) {
  return EEPROM.read(addresss);
}

//========================================================================

void printDangerZoneMenu(int menuCounter) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(50, 30);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(RED);
  M5.Lcd.println("Danger Zone");
  M5.Lcd.println("");
  M5.Lcd.setTextSize(2);
  if (menuCounter == 0) {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Remove account");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Restore from seed");
    M5.Lcd.println(" Reset device");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 1) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Remove account");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Restore from seed");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Reset device");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 2) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Remove account");
    M5.Lcd.println(" Restore from seed");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Reset device");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 3) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Remove account");
    M5.Lcd.println(" Restore from seed");
    M5.Lcd.println(" Reset device");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Back");
  }
}

//=======================================================================

void enterDangerZone() {
  int menuCounter = 0;
  printDangerZoneMenu(menuCounter);
  M5.update();
    bool loopMenu = true;
    int numOfItems = 4;
    while (loopMenu) {
      if (M5.BtnA.wasReleased())
      {
        menuCounter = mod(menuCounter - 1, numOfItems);
        printDangerZoneMenu(menuCounter);
      }
      else if (M5.BtnC.wasReleased())
      {
        menuCounter = mod(menuCounter + 1, numOfItems);
        printDangerZoneMenu(menuCounter);
      }
      else if (M5.BtnB.wasReleased())
      {
        loopMenu = false;
      }
      M5.update();
    }

  if (menuCounter == 0) {
    //remove account
  }
  else if (menuCounter == 1) {
    //restore from seed
  }
  else if (menuCounter == 2) {
    wipeDevice();
  }
  else {
    loop();
  }
}

//========================================================================

Account createNewAccount() {
  Account nullAccount;
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 30);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.println("  CHOOSE NAME OF ACCOUNT");
  String accountName = inputWords(1);
  if(accountName == "") return nullAccount;
  bool unique = true;
  File rFile = SD.open("/account.txt");
  String acc = rFile.readStringUntil(EOF);
  rFile.close();
  int found = acc.indexOf(accountName);
  if(found > -1) {
    String existingAccount = "";
    while(acc[found] != '*') {
      existingAccount += acc[found];
      found++;
    }
    if(accountName == existingAccount) {
      unique = false;
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setTextColor(RED);
      M5.Lcd.setCursor(10,50);
      M5.Lcd.println("Account name already exists!");
      delay(3000);
      createNewAccount();
      return nullAccount;
    }
  }


  int id = 0;
  String derivationPath = "";

  if(accountName.length() < 20 && unique) {
    if(acc.length() > 2) {
        int i = acc.length() - 1;
        while(acc[i] != '*' || i == 0) {
          i--;
        }
        i++;
        String id_str = "";
        do {
          id_str = id_str + acc[i];
          i++;
        } while (acc[i] != '/' || i == acc.length() - 1);
        id = id_str.toInt() + 1; //next address
    }

    derivationPath = "m/84'/0'/" + (String)id + "'/";
    File accFile = SD.open("/account.txt", FILE_APPEND);
    accFile.println(accountName + "*" + id + "/0");
    accFile.close();
  }
  else {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 30);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println("Error");
  }
  Account account(accountName, derivationPath);
  showPrompt("Switch to account?");
  while(M5.BtnA.wasReleased() == false && M5.BtnC.wasReleased() == false) {
    M5.update();
    if(M5.BtnC.wasReleased()) {
      account_ = account;
    }
  }
  return account;
}

//========================================================================

void printAccounts(int accountIndex, int numOfAccounts, std::vector<String> accountNames) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setCursor(0,10);
  M5.Lcd.println("Choose account\n");
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.setTextSize(2);
  for(int i = 0; i < numOfAccounts; i++) {
    if(i == accountIndex) {
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.println(">" + accountNames[accountIndex]);
    }
    else {
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println(" " + accountNames[i]);
    }
  }
}

//=========================================================================

Account selectAccount() {
  std::vector<String> accounts = indexAccounts();
  std::vector<String> accountNames = getAccountNames(accounts);
  int accountIndex = 0;
  int numOfAccounts = accounts.size();
  if(numOfAccounts == 0) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setTextSize(3);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.setCursor(10, 50);
    M5.Lcd.println("No accounts found");
    delay(100000);
  }
  String name = "";
  String derivationPath = "";
  printAccounts(accountIndex, numOfAccounts, accountNames);
  M5.update();
  while(M5.BtnB.wasReleased() == false) {
    M5.update();
    if(M5.BtnB.wasReleased()) {
      displayLoadingBar(0);
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setCursor(10, 100);
      M5.Lcd.setTextColor(GREEN);
      M5.Lcd.println("   Loading Account..");
      String account_str = accounts[accountIndex];
      int i = 0;
      while(account_str[i] != '*') {
        i++;
      }
      i++;
      displayLoadingBar(10);
      String tmp = "";
      while(account_str[i] != '/') {
        tmp = tmp + account_str[i];
        i++;
      }
      displayLoadingBar(20);
      name = accountNames[accountIndex];
      derivationPath = "m/84'/0'/" + tmp + "'/";

    }
    if(M5.BtnA.wasReleased()) {
      accountIndex = mod(accountIndex - 1, numOfAccounts);
      printAccounts(accountIndex, numOfAccounts, accountNames);
    }
    if(M5.BtnC.wasReleased()) {
      accountIndex = mod(accountIndex + 1, numOfAccounts);
      printAccounts(accountIndex, numOfAccounts, accountNames);
    }
  }
  displayLoadingBar(40);
  Account selectedAccount(name, derivationPath);
  displayLoadingBar(90);
  return selectedAccount;
}

//==========================================================================

void displayLoadingBar(int percent) {
  M5.Lcd.fillRect(35,140,240,20,0);
  M5.Lcd.progressBar(35,140,240,20, percent);
}

//===========================================================================

std::vector<String> indexAccounts() {
  File rFile = SD.open("/account.txt");
  String acc = rFile.readString();
  rFile.close();
  std::vector<String> accounts = std::vector<String>();
  String tmp = "";
  for(char c : acc) {
    if(c == '\n') {
      accounts.push_back(tmp);
      tmp = "";
    }
    else {
      tmp = tmp + c;
    }
  }
  return accounts;
}

//=========================================================================

std::vector<String> getAccountNames(std::vector<String> accounts) {
  std::vector<String> accountNames = std::vector<String>();
  for(String account : accounts) {
    int i = 0;
    String tmp = "";
    while(account[i] != '*') {
      tmp = tmp + account[i];
      i++;
    }
    accountNames.push_back(tmp);
  }
  return accountNames;
}

//========================================================================

void drawInputAccount() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setCursor(10, 30);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Enter account name");
  M5.Lcd.setCursor(10, 180);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.println("Hold home button to save");
  M5.Lcd.setTextColor(YELLOW);
  M5.Lcd.println("   Press once to exit");
  M5.Lcd.setTextColor(0x3a59);
  M5.Lcd.setCursor(10, 100);
}

//==========================================================================

String inputWords(int numOfWords) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextSize(2);
  int alphaIndex = 0;
  int enteredWords = 0;
  String currWord;
  String currLetter = "a";
  drawInputAccount();
  M5.Lcd.setTextColor(WHITE);
  M5.Lcd.print(currLetter);
  M5.update();
  while(enteredWords < numOfWords) {

    if(M5.BtnA.wasPressed()) {
      buttonA = true;
    }
    if(M5.BtnB.wasPressed()) {
      buttonB = true;
    }
    if(M5.BtnC.wasPressed()) {
      buttonC = true;
    }

    if(M5.BtnA.wasReleased() && !buttonC) {
      buttonA = false;
      drawInputAccount();
      alphaIndex = mod(alphaIndex - 1, 28);
      currLetter = extendedAlphabet[alphaIndex];
      M5.Lcd.print(currWord);
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.print(currLetter);
      M5.Lcd.setTextColor(GREEN);
    }
    else if(M5.BtnC.wasReleased() && !buttonA) {
      buttonC = false;
      drawInputAccount();
      alphaIndex = mod(alphaIndex + 1, 28);
      currLetter = extendedAlphabet[alphaIndex];
      M5.Lcd.print(currWord);
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.print(currLetter);
      M5.Lcd.setTextColor(GREEN);
    }
    else if(M5.BtnC.wasReleased() && (buttonA && buttonC)) {
      buttonA = false;
      buttonC = false;
      drawInputAccount();
      currWord = currWord + extendedAlphabet[alphaIndex];
      alphaIndex = 0;
      currLetter = extendedAlphabet[alphaIndex];
      M5.Lcd.print(currWord);
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.print(currLetter);
      M5.Lcd.setTextColor(GREEN);
    }
    else if(M5.BtnB.pressedFor(2000)) {
      enteredWords++;
      M5.Lcd.fillScreen(BLACK);
    }
    else if(M5.BtnB.wasReleased()) {
      showPrompt("Exit to home?");
      while(M5.BtnC.wasReleased() == false && M5.BtnA.wasReleased() == false) {
        M5.update();
        if(M5.BtnC.wasReleased()) {
          return "";
        }
      }
      drawInputAccount();
      M5.Lcd.print(currWord);
      M5.Lcd.setTextColor(WHITE);
      M5.Lcd.print(currLetter);
      M5.Lcd.setTextColor(GREEN);
    }
    M5.update();
  }
  return currWord;
}

//======================================================================

void drawBtcUnitSwitch(String unit) {
  if(unit == "sat") {
    M5.Lcd.fillRect(M5.Lcd.getCursorX() + 20, M5.Lcd.getCursorY(), 55, 17, 0xFDA0); //sats orange
    M5.Lcd.setTextColor(BLACK);
    M5.Lcd.print("  sats");
    M5.Lcd.drawRect(M5.Lcd.getCursorX() + 2, M5.Lcd.getCursorY(), 55, 17, 0x7BEF); //btc dark grey
    M5.Lcd.setTextColor(0x7BEF);
    M5.Lcd.println(" btc");
  }
  else if (unit == "btc") {
    M5.Lcd.drawRect(M5.Lcd.getCursorX() + 20, M5.Lcd.getCursorY(), 55, 17, 0x7BEF); //sats dark grey
    M5.Lcd.setTextColor(0x7BEF);
    M5.Lcd.print("  sats");
    M5.Lcd.fillRect(M5.Lcd.getCursorX() + 2, M5.Lcd.getCursorY(), 55, 17, 0xFDA0); //btc orange
    M5.Lcd.setTextColor(BLACK);
    M5.Lcd.println(" btc");
  }
  else {
    Serial.println("Invalid unit option");
  }
}

//======================================================================

void printSettingsMenu(int menuCounter) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(50, 30);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.println("Settings");
  M5.Lcd.println("");
  M5.Lcd.setTextSize(2);
  if (menuCounter == 0) {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Change Account Name");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Pin");
    M5.Lcd.println(" Set Max Fee");
    M5.Lcd.print(" Bitcoin unit");
    drawBtcUnitSwitch(bitcoinUnit);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 1) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Account Name");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Change Pin");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Set Max Fee");
    M5.Lcd.print(" Bitcoin unit");
    drawBtcUnitSwitch(bitcoinUnit);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 2) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Account Name");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Pin");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Set Max Fee");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print(" Bitcoin unit");
    drawBtcUnitSwitch(bitcoinUnit);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 3) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Account Name");
    M5.Lcd.println(" Change Pin");
    M5.Lcd.println(" Set Max Fee");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.print(">Bitcoin unit");
    drawBtcUnitSwitch(bitcoinUnit);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 4) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Account Name");
    M5.Lcd.println(" Change Pin");
    M5.Lcd.println(" Set Max Fee");
    M5.Lcd.print(" Bitcoin unit");
    drawBtcUnitSwitch(bitcoinUnit);
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Back");
  }
}

//=======================================================================

void settingsMenu(int menuCounter = 0) {
  printSettingsMenu(menuCounter);
  M5.update();
    bool loopMenu = true;
    int numOfItems = 5;
    while (loopMenu) {
      if (M5.BtnA.wasReleased())
      {
        menuCounter = mod(menuCounter - 1, numOfItems);
        printSettingsMenu(menuCounter);
      }
      else if (M5.BtnC.wasReleased())
      {
        menuCounter = mod(menuCounter + 1, numOfItems);
        printSettingsMenu(menuCounter);
      }
      else if (M5.BtnB.wasReleased())
      {
        loopMenu = false;
      }
      M5.update();
    }

  if (menuCounter == 0) {
    //change account name
  }
  else if (menuCounter == 1) {
    //change pin code
  }
  else if (menuCounter == 2) {
    setMaxFee();
  }
  else if (menuCounter == 3) {
    bitcoinUnit = (bitcoinUnit == "btc") ? "sat" : "btc";
  }


  if (menuCounter == 4) {
    loop();
  }
  else {
    settingsMenu(menuCounter);
  }
}

//======================================================================

void printFeeMenu(bool warnFeeSet, bool maxFeeSet) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0,0);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Change Max Fee");
  M5.Lcd.println();
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.setTextSize(2);
  M5.Lcd.print("Warn fee percent ");
  if(!warnFeeSet) {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
  }
  M5.Lcd.println(warnFeePercent_);
  M5.Lcd.setTextColor(GREEN);
  M5.Lcd.print("Max fee percent ");
  if(!maxFeeSet && warnFeeSet) {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
  }
  M5.Lcd.println(maxFeePercent_);
  if(warnFeeSet && maxFeeSet) {
    M5.Lcd.setCursor(40, 210);
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.print("Help");
    M5.Lcd.setCursor(135, 210);
    M5.Lcd.setTextColor(0x3a59);
    M5.Lcd.print("Home");
    M5.Lcd.setCursor(230, 210);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print("Save");
  }
}

//========================================================================

void setMaxFee() {

  bool warnFeeSet = false;
  bool maxFeeSet = false;
  printFeeMenu(warnFeeSet, maxFeeSet);
  while(!warnFeeSet || !maxFeeSet) {
    M5.update();
    delay(10);
    if(M5.BtnA.wasReleased() && !warnFeeSet) {
      warnFeePercent_--;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    else if(M5.BtnC.wasReleased() && !warnFeeSet) {
      warnFeePercent_++;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    else if(M5.BtnB.wasReleased() && !maxFeeSet && !warnFeeSet) {
      warnFeeSet = true;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    else if(M5.BtnA.wasReleased() && !maxFeeSet && warnFeeSet) {
      maxFeePercent_--;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    else if(M5.BtnC.wasReleased() && !maxFeeSet && warnFeeSet) {
      maxFeePercent_++;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    else if(M5.BtnB.wasReleased() && !maxFeeSet && warnFeeSet) {
      maxFeeSet = true;
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
  }
  bool saved = false;
  M5.update();
  while(saved == false) {
    M5.update();
    delay(10);
    if(M5.BtnA.wasReleased()) {
      //show help
      printFeeMenu(warnFeeSet, maxFeeSet);
    }
    if(M5.BtnB.wasReleased()) {
      return; //home
    }
    if(M5.BtnC.wasReleased()) {
      saved = true;
    }
  }
}

//=====================================================================

void printAdvancedMenu(int menuCounter) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(50, 30);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.println("Advanced");
  M5.Lcd.println("");
  M5.Lcd.setTextSize(2);
  if (menuCounter == 0) {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Export ZPUB");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export addresses");
    M5.Lcd.println(" Export Wallet");
    M5.Lcd.println(" Change Gap Limit");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 1) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export ZPUB");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Export addresses");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export Wallet");
    M5.Lcd.println(" Change Gap Limit");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 2) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export ZPUB");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export addresses");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Export Wallet");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Change Gap Limit");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 3) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export ZPUB");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export addresses");
    M5.Lcd.println(" Export Wallet");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Change Gap Limit");
    M5.Lcd.setTextColor(YELLOW);
    M5.Lcd.println(" Back");
  }
  else if (menuCounter == 4) {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export ZPUB");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Export addresses");
    M5.Lcd.println(" Export Wallet");
    M5.Lcd.println(" Change Gap Limit");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Back");
  }
}

//======================================================================

void advancedMenu(int menuCounter = 0) {
  printAdvancedMenu(menuCounter);
  M5.update();
    bool loopMenu = true;
    int numOfItems = 5;
    while (loopMenu) {
      if (M5.BtnA.wasReleased())
      {
        menuCounter = mod(menuCounter - 1, numOfItems);
        printAdvancedMenu(menuCounter);
      }
      else if (M5.BtnC.wasReleased())
      {
        menuCounter = mod(menuCounter + 1, numOfItems);
        printAdvancedMenu(menuCounter);
      }
      else if (M5.BtnB.wasReleased())
      {
        loopMenu = false;
      }
      M5.update();
    }

  if (menuCounter == 0) {
    exportMaster();
  }
  else if (menuCounter == 1) {
    account_.exportAddresses();
  }
  else if(menuCounter == 2) {
    exportWallet();
  }
  else if(menuCounter == 3) {
    changeGapLimit();
  }

  if (menuCounter == 4) {
    loop();
  }
  else {
    advancedMenu(menuCounter);
  }

}

//========================================================================

void printMainMenu(int menuCounter) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(10, 30);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.println(account_.getAccountName());
  M5.Lcd.println("");
  M5.Lcd.setTextSize(2);
  if (menuCounter == 0)
  {
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Receive");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
  }
  else if (menuCounter == 1)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Sign Transaction");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
  }
  else if (menuCounter == 2)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Switch Account");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
  }
  else if (menuCounter == 3)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Create New Account");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
  }
  else if (menuCounter == 4)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Test Mnemonic Phrase");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
  }
  else if (menuCounter == 5)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Settings");
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
    M5.Lcd.setTextColor(0x3a59);
  }
  else if (menuCounter == 6)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Advanced");
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println(" Danger Zone");
    M5.Lcd.setTextColor(0x3a59);
  }
  else if (menuCounter == 7)
  {
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.println(" Receive");
    M5.Lcd.println(" Sign Transaction");
    M5.Lcd.println(" Switch Account");
    M5.Lcd.println(" Create New Account");
    M5.Lcd.println(" Test Mnemonic Phrase");
    M5.Lcd.println(" Settings");
    M5.Lcd.println(" Advanced");
    M5.Lcd.setTextColor(WHITE, 0x3a59);
    M5.Lcd.println(">Danger Zone");
    M5.Lcd.setTextColor(0x3a59);
  }
}

//========================================================================

void printExportWalletMenu(int &menuCounter, std::vector<String> accountNames, int accountIDSelected) {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0,0);
  M5.Lcd.setTextColor(BLUE);
  M5.Lcd.setTextSize(3);
  M5.Lcd.println("Choose account");
  M5.Lcd.setTextSize(2);
  M5.Lcd.println();
  for(int i = 0; i < accountNames.size(); i++) {
    if(i == menuCounter) {
      M5.Lcd.setTextColor(WHITE, 0x3a59);
    }
    else {
      M5.Lcd.setTextColor(GREEN);
    }
    M5.Lcd.print(accountNames[i]);
    M5.Lcd.setTextSize(1);
    M5.Lcd.setTextColor(GREEN);
    M5.Lcd.print("  m/84'/0'/" + (String)accountIDSelected + "'/");
    M5.Lcd.setTextSize(2);
    M5.Lcd.println();
  }
}

//=========================================================================

void exportWallet() {
  std::vector<String> accounts = indexAccounts();
  std::vector<String> accountNames = getAccountNames(accounts);
  int menuCounter = 0;
  int accountIDSelected = account_.getAccountID();
  int currentAccount = account_.getAccountID(); //select current account
  printExportWalletMenu(menuCounter, accountNames, accountIDSelected);
  String accountStr = accounts[menuCounter];
  M5.update();
  while(M5.BtnB.wasReleased() == false) {
    M5.update();
    delay(10);
    if(M5.BtnA.wasPressed()) {
      buttonA = true;
    }
    if(M5.BtnC.wasPressed()) {
      buttonC = true;
    }
    if(M5.BtnA.wasReleased() && !buttonC) {
      buttonA = false;
      menuCounter = (menuCounter - 1) % accountNames.size();
      accountStr = accounts[menuCounter];
      accountIDSelected = getAccountId(accountStr);
      printExportWalletMenu(menuCounter, accountNames, accountIDSelected);
    }
    if(M5.BtnC.wasReleased() && !buttonA) {
      buttonC = false;
      menuCounter = (menuCounter + 1) % accountNames.size();
      accountStr = accounts[menuCounter];
      accountIDSelected = getAccountId(accountStr);
      printExportWalletMenu(menuCounter, accountNames, accountIDSelected);
    }
    if(buttonA && buttonC) {
      buttonA = false;
      buttonC = false;
      //get id from name
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.println(accountNames[menuCounter]);
      int id = getAccountId(accountStr);
      Account exportAccount = Account(getAccountName(accountStr), "m/84'/0'/" + (String)id + "'/'");
      delay(5000);
      if(createGenericWallet(exportAccount) == false) {
        M5.Lcd.setTextColor(RED);
        M5.Lcd.setTextSize(2);
        M5.Lcd.setCursor(0, 100);
        M5.Lcd.println("Could not write file");
        delay(2000);
      }
    }
    if(M5.BtnB.wasReleased()) {
      return; //home
    }
  }

}

//========================================================================

int getAccountId(String accountStr) {
  String accountId = "";
  for(int i = 0; i < accountStr.length(); i++) {
    if(accountStr[i] == '*') {
      i++;
      while(accountStr[i] != '/') {
        accountId += accountStr[i];
        i++;
      }
    }
  }
  return accountId.toInt();
}

//=========================================================================

String getAccountName(String accountStr) {
  int i = 0;
  String name = "";
  while(accountStr[i] != '*') {
    name += accountStr[i];
    i++;
  }
  return name;
}

//==========================================================================

bool createGenericWallet(Account account) {
  Serial.println(account.getAccountID());
  Serial.println(account.getDerivationPath());
  return true;
}

//======================================================================

void loop() {
  loopMenu = true;
  int numOfItems = 8;
  M5.update();
  printMainMenu(menuItem);
    while (M5.BtnB.wasReleased() == false) {
      if (M5.BtnA.wasReleased()) {
        menuItem = mod(menuItem - 1, numOfItems);
        printMainMenu(menuItem);
      }
      else if (M5.BtnC.wasReleased()) {
        menuItem = mod(menuItem + 1, numOfItems);
        printMainMenu(menuItem);
      }
      M5.update();
    }

switch (menuItem) {
  case 0:
    account_.Receive();
    break;
  case 1:
    account_.signPSBT();
    break;
  case 2: //switch account
    account_ = selectAccount();
    break;
  case 3:
    createNewAccount();
    break;
  case 4:
    testMnemonic();
    break;
  case 5:
    settingsMenu(0); //enter with menu item 1
    break;
  case 6:
    advancedMenu(0); //enter with menu item 1
    break;
  case 7:
    enterDangerZone();
    break;
  }
}

//===============================================================

void setup() {

  M5.begin();
  Serial.begin(9600);
  delay(200);
  M5.Lcd.loadFont("Roboto-Light", SD);
  File keyFile = SD.open("/key.txt");
  privateKey = keyFile.readStringUntil('\n');
  keyFile.close();
  bool sdSwitch = false;
  while(!sdSwitch) {
    sdChecker();
    if(privateKey.length() < 100) {
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setCursor(0, 100);
      M5.Lcd.setTextSize(2);
      M5.Lcd.setTextColor(RED);
      M5.Lcd.println("No wallet found on device");
      seedMaker();
      pinMaker();
    }
    else if(!sdAvailable) {
      M5.Lcd.fillScreen(BLACK);
      M5.Lcd.setCursor(0, 100);
      M5.Lcd.setTextSize(2);
      M5.Lcd.setTextColor(RED);
      M5.Lcd.println(" ERROR: No SD available");
    }
    else {
      sdSwitch = true;
    }
    Serial.println(sdCommand);
    delay(3000);
  }

  if (sdCommand == "HARD RESET")
  {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 20);
    M5.Lcd.setTextSize(3);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println("");
    M5.Lcd.setCursor(0, 90);
    M5.Lcd.println("    PROCESSING");
    delay(1000);
    //wipeSD();
    seedMaker();
    pinMaker();
  }
  else if (sdCommand.substring(0, 7) == "RESTORE")
  {
    //wipeSD();
    restoreFromSeed(sdCommand.substring(8, sdCommand.length()));
    pinMaker();
  }
  else if (privateKey.length() > 100){
    File passFile = SD.open("/pass.txt");
    String pass = passFile.readStringUntil('\n');
    passFile.close();
    if(pass.length() < 60) {
      M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 100);
    M5.Lcd.setTextSize(2);
      M5.Lcd.println("  Create new passphrase");
      delay(2000);
      enterPin(true);
    }
    else {
      enterPin(false);
    }
  }
  else
  {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 100);
    M5.Lcd.setTextSize(2);
    M5.Lcd.setTextColor(RED);
    M5.Lcd.println("ERROR: 'HARD RESET' device");
    delay(999999999);
  }

  M5.Lcd.setBrightness(20);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(30,10);
  M5.Lcd.setTextSize(3);
  M5.Lcd.setTextColor(0x5a39);
  M5.Lcd.println("Bluejay Wallet");
  M5.Lcd.drawJpgFile(SD, "/bluejay.jpg",80, 40, 232, 193);
  //M5.Lcd.drawJpgFile(SD, "/padlock.jpg",40, 40, 90, 90);
  M5.Lcd.setCursor(10, 220);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Your Keys, Your Coins");
  delay(2000);
  account_ = selectAccount();
  displayLoadingBar(100);
  delay(50);
}
