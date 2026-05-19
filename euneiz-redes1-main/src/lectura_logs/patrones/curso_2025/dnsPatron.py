from lectura_logs.PatronPadre import PatronPadre


class dnsPatron(PatronPadre):
    '''
    Clase patrón del protocolo DNS (Domain Name System)
    '''
    dict_values = [
        "layer_name", "id", "flags", "qr", "opcode", "aa", "tc", "rd", "ra",
        "rcode", "count_queries", "count_answers", "count_auth_rr", "count_add_rr",
        "qry_name", "qry_type", "qry_class", "a", "cname", "resp_ttl"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'dns.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'dns' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['dns']:
                        resultado[x] = data_string['layers']['dns'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
