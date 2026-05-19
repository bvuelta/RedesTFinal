from lectura_logs.PatronPadre import PatronPadre


class tcpPatron(PatronPadre):
    '''
    Clase patrón del protocolo TCP (Transmission Control Protocol)
    '''
    dict_values = [
        "layer_name", "srcport", "dstport", "seq", "ack", "hdr_len",
        "flags", "flags_syn", "flags_ack", "flags_fin", "flags_reset", "flags_push", "flags_urg",
        "window_size", "checksum", "checksum_status", "urgent_pointer"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'tcp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'tcp' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['tcp']:
                        resultado[x] = data_string['layers']['tcp'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
