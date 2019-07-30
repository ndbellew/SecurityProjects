
#firewall.sh
#Author: Nathan Bellew
#Firewall UI screen that manipulates the iptables to make
#changing your firewall less of a hassle :)
#Requirements to fullfil (for me to make in program)
# - Script should be a standalone program that can be run from a terminal
# - The script should provide help menu. a Help feature with commands.
# - The script should make it easier to add, delete, and modify firewall rules.
# - The script should provide functionality to export the existing rules to a
#   "nicely" formatted HTML report file. - it definitely makes one
AltCommands() {
  #send them here in the menu if statements if you have general commands that can be run anywhere.
  if [[ $1 == "Exit" ]];then
    iptables-save > post_firewall_changes.txt
    exit 1
  elif [[ $1 == "AllowAllTraffic" ]]; then
    echo "By allowing all traffic all of your other rules will be flushed. Stay safe!"
    sudo iptables -P INPUT ACCEPT
    sudo iptables -P FORWARD ACCEPT
    sudo iptables -P OUTPUT ACCEPT
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    sudo iptables -F
    sudo iptables -X
    echo "All network traffic will be allowed."
  elif [[ $1 == "FlushAll" ]]; then
    sudo iptables -F
  else
    echo "This was not a correct option, please input a number from the list."
    echo "Please type [ENTER] to try again"
    read ans
  fi
  echo "here"
}

AddRuleHelp() {
  if [[ $1 == "1" || $1 == "2" ]]; then
    #This explains tables and Chains good enough no need to write more.
    echo "Filter - This is the defualt table, the chains are"
    echo "    Input: Packets going to local sockets"
    echo "    Forward: Packets routed through server"
    echo "    Output: Locally generated packets"
    echo "Nat - Whenever a packet creates a new connection."
    echo "    Prerouting: designating packets when they come in"
    echo "    Output: locally generated packets before routing takes place"
    echo "    Postrouting: altering packets on the way out"
    echo "Mangle - Used for special altering of packets"
    echo "    Prerouting: incoming packets"
    echo "    Postrouting: outgoing packets"
    echo "    Output: locally generated packets that are being altered"
    echo "    Input: packets coming directly into the server"
    echo "    Forward: packets being routed through the server"
    echo "Raw - Primarily used for configuring exemptions for connnection tracking."
    echo "    Prerouting: packets that arrive by the network interface"
    echo "    Output: processes that are locally generated"
    echo "Security: Used for Mandatory Access Control (MAC) rules, Generally in line after the filter table."
    echo "    Input: packets entering the server"
    echo "    Output: locally generated packets"
    echo "    Forward: packets passing through the server"

  else
    echo "TBD"
fi
}

DefineTable() {
  read TableAns
  if [[ $TableAns == "raw" || $TableAns == "RAW" ]]; then
    table="raw"
  elif [[ $TableAns == "nat" || $TableAns == "NAT" ]]; then
    table="nat"
  elif [[ $TableAns == "security" || $TableAns == "SECURITY" ]]; then
    table="security"
  elif [[ $TableAns == "mangle" || $TableAns == "MANGLE" ]]; then
    table="mangle"
  elif [[ $TableAns == "filter" || $TableAns == "FILTER" ]]; then
    table="filter"
  elif [[ $TableAns == "help" ]]; then
    AddRuleHelp "1"
    echo "Press ENTER to continue"
    read ENTER
    clear
    DefineTable
  else
    echo "Your response was incorrect please press [ENTER] to try again."
    read enter
    clear
    DefineTable
  fi

  if [[ -n "$table" ]]; then
    sudo iptables -t $table -L
  else
    clear
    DefineTable
  fi
}

DefineChain() {
  echo "What chain would you like to focus on? (help)"
  read response
  if [[ $response == "input" || $response == "INPUT" ]]; then
    chain="INPUT"
  elif [[ $response == "forward" || $response == "FORWARD" ]]; then
    chain="FORWARD"
  elif [[ $response == "output" || $response == "OUTPUT" ]]; then
    chain="OUTPUT"
  elif [[ $response == "prerouting" || $response == "PREROUTING" ]]; then
    chain="PREROUTING"
  elif [[ $response == "postrouting" || $response == "POSTROUTING" ]]; then
    chain="POSTROUTING"
  elif [[ $response == "help" ]]; then
    AddRuleHelp 2
    echo "Press [ENTER] to continue."
    read ENTER
    clear
    DefineChain
  # CHAINS=('INPUT', 'FORWARD','OUTPUT', 'PREROUTING', 'POSTROUTING')
  else
    chain=$response
    echo "Your response was not one of the most common chains, we will still attempt to use it."
    echo "Please Note if this is not a real chain or is not all in caps (ex. POSTROUTING, INPUT)"
    echo -n "If this is the case please enter retry to do it again. otherwise press enter to continue."
    read enter
    if [[ $enter == "retry" || $enter == "Retry" ]]; then
      clear
      DefineChain
    fi
  fi

  if [[ -n "$chain" ]]; then
    sudo iptables -L $chain

  else
    clear
    DefineChain
  fi
}

AddRulePortDest (){
    echo "Would you like to select a port destination? [y/n]"
    read AnswerPort
    if [[ $AnswerPort == "y" ]]; then
      echo "What is your port number?"
      read Port
    fi
}

AddRuleProtocol() {
  echo "What Protocol do you want to use? (tcp, udp, icmp, all) (help)"
  read ProtocolAns
  if [[ $ProtocolAns == "help" ]]; then
    echo "Each protocol targets that specific type of file/packet when your computer recieves"
    echo "all will assume all protocols. You are allowed to name one of the none basic protocols, just note"
    echo -n " if they are not a correct port the rule will fail and not be added."
    echo "No ports need to be selected necessarily to add a rule. "
    echo "Press Enter when you are ready to try it out, or type Menu to return to main menu"
    read HelpOption
    if [[ $HelpOption == "Menu" || $HelpOption == "menu" || $HelpOption == "MENU" ]]; then
      MainMenu
    else
      AddRuleHelp
    fi
  elif [[ $ProtocolAns == "tcp" || $ProtocolAns == "TCP" ]]; then
    Protocol="tcp"
  elif [[ $ProtocolAns == "udp" || $ProtocolAns == "UDP" ]]; then
    Protocol="udp"
  elif [[ $ProtocolAns == "icmp" || $ProtocolAns == "ICMP" ]]; then
    Protocol="icmp"
  elif [[ $ProtocolAns == "all" || $ProtocolAns == "ALL" ]]; then
    Protocol="all"
  else
    echo "You entered a Protocol that is not on the basic list, if you want to retry"
    echo -n "please type retry"
    read protocolSecondChance
    if [[ $protocolSecondChance == "retry" ]]; then
      clear
      sudo iptables -L $chain
      AddRuleProtocol
    fi
  fi
}

AddRuleInsertOrAppend() {
  echo "Would you like to add the as Last or Inserted? (help)"
  read AnstoLoc
  if [[ $AnstoLoc == "last" || $AnstoLoc == "Last" ]]; then
    Location="Append"
  elif [[ $AnstoLoc == "inserted" || $AnstoLoc == "Inserted" ]]; then
    Location="Insert"
    echo "What number location do you want it to be inserted?"
    #sudo iptalbes -L $chain -t $table --line-numbers
    read LocationNumber
  elif [[ $anstoLoc == "help" ]]; then
    echo "By inserting it the rule will be read in the listed location you put, if you simply append it it will be added last and therefore not seen until all other rules."
    AddRuleInsertOrAppend
  else
    echo "incorrect input please press Enter to try again."
    read FAILURE
    AddRuleInsertOrAppend

  fi
}

AddRuleSource () {
  echo "What would you like your source to be, Note that the source can be an IP address, hostname, network name, etc."
  read Source
}

AddRuleTarget () {
  echo "What Target would you like, Possible choices are"
  echo -e -n "\nACCEPT\nDROP\nQUEUE\nRETURN\n(help)"
  read AnsTarget
  if [[ $AnsTarget == "help" ]]; then
    echo -e "ACCEPT means to let the packet through\nDROP means to drop the packet on the floor. QUEUE means to pass the packet to userspace. (How the packet can be received by a userspace process differs by the particular queue handler. 2.4.x and 2.6.x kernels up to 2.6.13 include the ip_queue queue handler. Kernels 2.6.14 and later additionally include the nfnetlink_queue queue handler.\nPackets with a target of QUEUE will be sent to queue number '0' in this case.\nRETURN means stop traversing this chain and resume at the next rule in the previous (calling) chain."
  else
    Target=$AnsTarget
  fi
}

AddRuleFinal () {
  if [[ $Location == "Append" ]]; then
    FinalRule="$FinalRule -A $chain -t $table -p $Protocol"
  else
    Finalrule="$FinalRule -A $chain $LocationNumber -t $table -p $Protocol"
  fi
  if [[ $Protocol == "udp" || $Protocol == "tcp" ]]; then
    if [[ $AnswerPort == "Y" ]]; then
    FinalRule="$FinalRule --dport $Port"
    fi
  fi
  FinalRule="$FinalRule -j $Target"
  if [[ -z $Source ]]; then
    FinalRule="$FinalRule -s anywhere"
  else
    FinalRule="$FinalRule -s $Source"
  fi
}

AddRule () {
  AddRuleInsertOrAppend
  AllRules
  echo "What table would you like to add your rule on?"
  DefineTable
  iptables -L -t $table
  DefineChain
  echo -e "Would you like to add a Source?\nIf no is selected the source 'anywhere' will be assumed. \n[y/n]"
  read sourceans
  if [[ $sourceans == "y" ]]; then
    AddRuleSource
  else
    Source="anywhere"
  fi
   #
  AddRuleTarget
  AddRuleProtocol
  if [[ $Protocol == "udp" || $Protocol == "tcp" ]]; then
    AddRulePortDest
  fi
  echo "Please add a comment to note what the rule is for, if you have none or are finished press enter"
  read Comment
  echo "Your current command is"
  if [[ $Location == "Append" ]]; then
    echo "sudo iptables -A $chain -t $table -p $Protocol --destination-port $Port -j $Target --comment $Comment -s $Source"
  else
    echo "sudo iptables -I $chain $LocationNumber -t $table -p $Protocol --destination-port $Port -j $Target --comment $Comment -s $Source"
  fi
  echo "If this is correct please type yes, otherwise lets try again!"
  read yesIhope
  if [[ $yesIhope != "yes" ]]; then
    clear
    AddRule
  else
    AddRuleFinal
  fi
  sudo iptables $FinalRule
}

HelpDeleteOptions () {
  echo "Iptables allows us two main options to removing rules:"
  echo "Delete:"
  echo "  you can either specify a specific rule to delete or specify the chain and line Number"
  echo "Flush:"
  echo "  Flush will remove an entire table of rules. this is equivalent to deleting all rules one by one."
  echo "Press Enter when you are ready to try it out, or type Menu to return to main menu"
  read HelpOption
  if [[ $HelpOption == "Menu" || $HelpOption == "menu" || $HelpOption == "MENU" ]]; then
    MainMenu
  else
    RemovingRule
  fi
}

DeleteRule () {
  AllRules
  echo "What table would you like?"
  DefineTable
  sudo iptables -L -t $table --line-numbers
  DefineChain
  sudo iptables -L $chain --line-numbers
  echo "Please input the chain number"
  read lineNumber
  echo "are you sure you want to delete $table $chain $lineNumber? [y/n]"
  read yn
  if [[ yn == "y" || yn == "yes" ]];then
    sudo iptables -D $chain $lineNumber -t $table
  else
    echo -e "Would you like to\n1) Return to Main Menu2) Return To Delete Menu3) Retry This Rule Deletion"
    read DelAns
    if [[ $DelAns == "1" ]]; then
      MainMenu
    elif [[ $DelAns == "2" ]]; then
      RemovingRule
    elif [[ $DelAns == "3" ]]; then
      DeleteRule
    else
      echo "Incorrect input restarting program. Press Enter to continue"
      read ENTER
      clear
      MainMenu
    fi
  fi
}

FlushRule () {
  AllRules
  echo "What table would you like?"
  DefineTable
  sudo iptables -L -t $table --line-numbers
  DefineChain
  sudo iptables -L $chain --line-numbers
  echo "are you sure you want to delete $table $chain? [y/n]"
  read yn
  if [[ yn == "y" || yn == "yes" ]];then
    sudo iptables -F $chain -t $table
  else
    echo -e "Would you like to\n1) Return to Main Menu2) Return To Delete Menu3) Retry This Rule Deletion"
    read DelAns
    if [[ $DelAns == "1" ]]; then
      MainMenu
    elif [[ $DelAns == "2" ]]; then
      RemovingRule
    elif [[ $DelAns == "3" ]]; then
      DeleteRule
    else
      echo "Incorrect input restarting program. Press Enter to continue"
      read ENTER
      clear
      MainMenu
    fi
  fi

}

RemovingRule() {
  echo "how would you like to delete your rule?"
  echo -e -n "1) Delete\n2) Flush\n3) Help\n"
  read ans
  if [[ $ans == "1" ]]; then
    DeleteRule
  elif [[ $ans == "2" ]]; then
    FlushRule
  elif [[ $ans == "3" ]]; then
    HelpDeleteOptions
  else
    echo -e "that was not the correct input, please input a number between 1-3\n please press enter to continue"
    read ans
  fi
}

ModifyRule() {
  AllRules
  echo "Please select a table"
  DefineTable
  sudo iptables -L -t $table --line-numbers
  DefineChain
  sudo iptables -L $chain --line-numbers
  echo "please select line number"
  read LineNumber
  echo "please type out the rule you would like to add in full. If you are Modifying this rule at $table $chain $LineNumber"
  echo -n "then you must know what you are doing. We will provide what is needed for its location."
  echo ""
  read RuleAddition
  sudo iptables -t $table -R $chain $LineNumber $RuleAddition
}

HelpEditFirewall() {
  echo "Add Rule will walk you through the steps for adding a Rule"
  echo ""
  echo "Delete rule will show you all tables so that you can select one chain to delete all rules or a specific rule."
  echo ""
  echo "Modify Rule, This one is more advanced and requires you to have knowledge of how to structure the way you replace the rule."
  echo ""
  echo "Quit will end program."
  echo ""
  echo "Help brought you here :)"
  echo ""
  EditFirewall
}

EditFirewall() {
  echo -e -n "1) Add Rule\n2) Delete Rule\n3) Modify Rule\n4) Quit\n5) Help\n"
  read response
  if [[ $response == "1" ]]; then
    AddRule
  elif [[ $response == "2" ]]; then
    RemovingRule
  elif [[ $response == "3" ]]; then
    ModifyRule
  elif [[ $response == "4" ]] || [[ $ans = "Quit" ]] || [[ $ans = "quit" ]]; then
    exit 1
  elif [[ $response == "5" ]]; then
    HelpEditFirewall
  else
    echo -e "that was not the correct input, please input a number between 1-3\n please press enter to continue"
    read enter
  fi
}

AllRules () {
  echo "FILTER ==============================================="
  iptables -L -n -t filter
  echo "NAT =================================================="
  iptables -L -n -t nat
  echo "MANGLE ==============================================="
  iptables -L -n -t mangle
  echo "RAW =================================================="
  iptables -L -n -t raw
  echo "SECURITY ============================================="
  iptables -L -n -t security
}

MainMenu () {
  while true; do
    echo "Welcome to the elaborate firewall menu."
    echo "Please select an option"
    echo -e "1) Check Current Iptable Rules\n2) Edit Firewall Rules\n3) Quit\n4) Help\n"
    read ans
    if [[ $ans == "1" ]]; then
      AllRules
    elif [[ $ans == "2" ]]; then
      EditFirewall
    elif [[ $ans == "3" ]]; then
      exit 1
    elif [[ $ans == "4" || $ans == "help" || $ans == "Help" ]]; then
      echo -e "1 will help you check your current rules"
      echo "will help you edit your current rules"
      echo  -e "will quit out of the system\n4 will display a help menu.\n please press [ENTER] when you are ready to try again."
    else# create a help so that is the main help so that it has all the information, the biggest info block in program
      #Then make all the other helps specialized, because the probably want to keep it simple at that point.
      AltCommands "$ans"
    fi
    clear
  done
}

main() {
  iptables-save > pre_firewall_changes.txt
  if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
  fi
  MainMenu
  iptables-save > post_firewall_changes.txt
}

main
