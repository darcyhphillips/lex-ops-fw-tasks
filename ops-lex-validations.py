import boto3
import json
import ipaddress


### Validate all slot information in Lex
def validate(slots):

    valid_fw_actions = ['add','modify','delete']
    
    if not slots['FirewallAction']:
        print("Inside Empty FirewallAction")
        return {
        'isValid': False,
        'violatedSlot': 'FirewallAction'
        }        
        
    if slots['FirewallAction']['value']['originalValue'].lower() not in valid_fw_actions:
        
        print("Not a valid entry")
        
        return {
        'isValid': False,
        'violatedSlot': 'FirewallAction',
        'message': 'We only support {} as valid entries.'.format(", ".join(valid_fw_actions))
        }

    valid_source_groups = ['vdi', 'surface', 'development']

    if not slots['SourceAction']:
        return {
        'isValid': False,
        'violatedSlot': 'SourceAction'
    }

    if slots['SourceAction']['value']['originalValue'].lower() not in valid_source_groups:
        
        print("Not a valid source group")
        
        return {
        'isValid': False,
        'violatedSlot': 'SourceAction',
        'message': 'We only support {} as valid source groups.'.format(", ".join(valid_source_groups))
        }

    ### written for eventual destination options ###
    
    # if not slots['DestinationAction']:
        
    #     return {
    #     'isValid': False,
    #     'violatedSlot': 'DestinationAction',
    # }
    
    # def validate_ip_address(ip_string):
    #     try:
    #         ipaddress.ip_address(ip_string)
    #         print("The IP address is valid.")
    #     except ValueError:
    #         print("The IP address is not valid")

    # destination_validation = slots['DestinationAction']['value']['originalValue']
    
    # if '10.10' in destination_validation:
    #     validate_ip_address(destination_validation)
    # elif 'test.com' not in destination_validation:
    #     print('Not a valid DNS name')
            
    #     return {
    #     'isValid': False,
    #     'violatedSlot': 'DestinationAction',
    #     'message': 'We only accept DNS names from test.com.?'
    #     }
        
    valid_protocols = ['https', 'rmq', 'iqplus']
    
    if not slots['PortAction']:
        return {
        'isValid': False,
        'violatedSlot': 'PortAction'
    }

    if slots['PortAction']['value']['originalValue'].lower() not in valid_protocols:
        
        print("Not a valid protocol")
        
        return {
        'isValid': False,
        'violatedSlot': 'PortAction',
        'message': 'We only support {} as valid protocols.'.format(", ".join(valid_protocols))
        }
        
    valid_types = ['tcp', 'udp']
    
    if not slots['TypeAction']:
        return {
        'isValid': False,
        'violatedSlot': 'TypeAction'
    }

    if slots['TypeAction']['value']['originalValue'].lower() not in valid_types:
        
        print("Not a valid type")
        
        return {
        'isValid': False,
        'violatedSlot': 'TypeAction',
        'message': 'We only support {} as valid types.'.format(", ".join(valid_types))
        }

    if not slots['SGAction']:
        return {
        'isValid': False,
        'violatedSlot': 'SGAction'
    }

    sg_entry = slots['SGAction']['value']['originalValue'].lower()
    sg_check = sg_entry.startswith('sg-')
    
    if sg_check is False:
        
        print("Invalid security group id")
        
        return {
        'isValid': False,
        'violatedSlot': 'SGAction',
        'message': 'You must begin your security group id with \'sg-\'.'
        }

    return {'isValid': True}
    
def lambda_handler(event, context):
    
    slots = event['sessionState']['intent']['slots']
    intent = event['sessionState']['intent']['name']
    print(event['invocationSource'])
    print(slots)
    print(intent)
    validation_result = validate(event['sessionState']['intent']['slots'])
    
### Will re-prompt in Lex if information is missing or does not match acceptable answers    
    if event['invocationSource'] == 'DialogCodeHook':
        if not validation_result['isValid']:
            
            if 'message' in validation_result:
            
                response = {
                "sessionState": {
                    "dialogAction": {
                        'slotToElicit':validation_result['violatedSlot'],
                        "type": "ElicitSlot"
                    },
                    "intent": {
                        'name':intent,
                        'slots': slots
                        
                        }
                },
                "messages": [
                    {
                        "contentType": "PlainText",
                        "content": validation_result['message']
                    }
                ]
               } 
            else:
                response = {
                "sessionState": {
                    "dialogAction": {
                        'slotToElicit':validation_result['violatedSlot'],
                        "type": "ElicitSlot"
                    },
                    "intent": {
                        'name':intent,
                        'slots': slots
                        
                        }
                }
               } 
    
            return response
           
        else:
            response = {
            "sessionState": {
                "dialogAction": {
                    "type": "Delegate"
                },
                "intent": {
                    'name':intent,
                    'slots': slots
                    
                    }
        
            }
        }
            return response

    
    if event['invocationSource'] == 'FulfillmentCodeHook':
        
        security_group_id = slots['SGAction']['value']['originalValue'].lower()
        protocol = slots['TypeAction']['value']['originalValue'].lower()
        cidr_ranges = {'vdi': '10.10.64.0/24', 'surface': '10.10.65.0/24', 'development': '192.168.0.0/24'}
        cidr = cidr_ranges.get(slots['SourceAction']['value']['originalValue'].lower()) 
        description = "test"
        ec2 = boto3.resource('ec2')
        security_group = ec2.SecurityGroup(security_group_id)
        port_ranges = {'https': [443], 'rmq': [5671, 5672, 15671, 15672]}
        ports = port_ranges.get(slots['PortAction']['value']['originalValue'].lower())
    
        for p in ports:
            port_range_start = p
            port_range_end = p
            security_group.authorize_ingress(
                    DryRun=False,
                    IpPermissions=[
                        {
                            'FromPort': port_range_start,
                            'ToPort': port_range_end,
                            'IpProtocol': protocol,
                            'IpRanges': [
                                {
                                    'CidrIp': cidr,
                                    'Description': description
                                },
                            ]
                        }
                    ]
                )

            
        response = {
        "sessionState": {
            "dialogAction": {
                "type": "Close"
            },
            "intent": {
                'name':intent,
                'slots': slots,
                'state':'Fulfilled'
                
                }
    
        },
        "messages": [
            {
                "contentType": "PlainText",
                "content": "Thanks, I have updated your security group"
            }
        ]
    }
        return response