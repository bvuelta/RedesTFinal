from lectura_logs.PatronPadre import PatronPadre


class arpPatron(PatronPadre):
    '''
    Clase patrón del protocolo ARP (Address Resolution Protocol)
    '''
    dict_values = [
        "layer_name", "hw_type", "proto_type", "hw_size", "proto_size",
        "opcode", "src_hw_mac", "src_proto_ipv4", "dst_hw_mac", "dst_proto_ipv4"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'arp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'arp' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['arp']:
                        resultado[x] = data_string['layers']['arp'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
