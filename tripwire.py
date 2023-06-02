#!/usr/bin/env python
"""
Author: 
    Gregory Frey

Description:
    Tripwire.py is an enhanced port of my Tripwire PowerShell script. The Python version utilizes both VMWare api (vmrest) and cli tool (vmrun).
    
    Requires Elasticsearch and Kibana to be running; Update kibana.yml with `xpack.encryptedSavedObjects.encryptionKey: "<32 character string>"`
   
New Features:
    - Elasticsearch case creation and alert management.
    - C2 Command logging
"""

import imports

imports.functions.title()

parser = imports.argparse.ArgumentParser()
parser.add_argument('-s', '--start', action="store_true", help="Starts virtual machines")
parser.add_argument('-x', '--stop', action="store_true", help="Starts virtual machines")
parser.add_argument('-l', '--launch', nargs='*', action="store", dest='case_name', required=False, help="Red Ranger will start monitoring for tripped alerts")
parser.add_argument('-i', '--information', action="store_true", help="Additional Information")
parser.add_argument('-n', '--name', type=str, help="User supplied case name")
args = parser.parse_args()

# Main Loop
def main():
    case_name = str(args.case_name)
        
    if args.information:        
        imports.functions.information()

    # Starts the virtual machines
    elif args.start:
        if imports.functions.vmrest_status() == False:
            imports.functions.vmrest()
            print(f"\n{imports.functions.log()} Started VMRest API")
            imports.time.sleep(1.0)

        print(f"{imports.functions.log()} Starting virtual machines...")
        
        imports.functions.startVM(imports.functions.get_VMids(), "on")

        print(f"{imports.functions.log()} Done\n")

    # Stops the virtual machines
    elif args.stop:
        print(f"\n{imports.functions.log()} Stopping virtual machines...")
        
        for vmx in imports.functions.getVMX():
            imports.functions.stopVM(vmx)

        print(f"{imports.functions.log()} Done\n")
    
    # Launches the lab. Enables Red Ranger to display alert information.
    # Will automatically continue any un-closed cases from the previous session.
    elif case_name:
        if case_name == None or args.case_name == None:
            imports.functions.information()
            quit()
            
        if len(args.case_name) == 0:
            case_name = "None"

        else:
            case_name = imports.functions.get_word()
        
        # ELK connection check:
        if imports.functions.check_elk() != True:
            print(f"{imports.colors.DEBUG}[!] ELK connection failed{imports.colors.END}\n")

        else:
            # Check for any open cases
            open_case = []
            case_list = imports.functions.getCases()

            for case in case_list:
                if case['status'] == 'in-progress':
                    open_case.append(case)
            
            if args.case_name:
                new_case = imports.functions.createCase(args.case_name)

                print(f"\nCase: {imports.colors.CYAN}{new_case['title']}{imports.colors.END}")
                imports.functions.tallyRules() 
                imports.functions.red_ranger(new_case['id'], new_case['version'])

            elif open_case:

                # Prints a list of open cases.
                print(f"\nOpen Cases:")
                for case in open_case:
                    title = case['title']
                    print(f"{(open_case.index(case))+1} | {imports.colors.CYAN}{case['title']}{imports.colors.END}")
                
                # User selects case or creates new case.
                choice = input("\nSelect case [number] to continue or [new] for new: ")

                if choice.lower() == 'new':
                    print(f"\n[*] Creating {imports.colors.GREEN}new{imports.colors.END} case\n")
                     
                    new_case = imports.functions.createCase(case_name)
                    print(f"Case: {imports.colors.CYAN}{new_case['title']}{imports.colors.END}")
                    imports.functions.tallyRules()   

                    imports.functions.red_ranger(new_case['id'], new_case['version'])
                    quit()
                
                if (not choice.isdigit()) or (int(choice) > len(open_case)):
                    print(f"\n{imports.colors.DEBUG}[!] Please select a case or create a new case.\n{imports.colors.END}")
                    quit()

                for case in open_case:
                    if (open_case.index(case) == int(choice)-1):
                    # if (str(case['title']) == choice.lower()) or (open_case.index(case) == int(choice)-1):
                        print(f"\nResuming {imports.colors.CYAN}{case['title']}{imports.colors.END}")
                        imports.functions.tallyRules()
                        # imports.functions.barbed_wire()
                        imports.functions.red_ranger(case['id'], case['version'])
                        quit()                                   

            else:
                new_case = imports.functions.createCase(case_name)
                print(f"\nCase: {imports.colors.CYAN}{new_case['title']}{imports.colors.END}")
                imports.functions.tallyRules()

                imports.functions.red_ranger(new_case['id'], new_case['version'])
                
    else:
        imports.functions.information()   

main()