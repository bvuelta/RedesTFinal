from lectura_logs.PatronPadre import PatronPadre


class tlsPatron(PatronPadre):
    '''
    Clase patrón del protocolo TLS/SSL (Transport Layer Security)
    '''
    dict_values = [
        "layer_name", "record_content_type", "record_version", "record_length",
        "handshake_type", "handshake_length", "handshake_version",
        "handshake_extensions_server_name", "handshake_ciphersuite",
        "handshake_session_id", "alert_message_desc"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'tls.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'tls' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['tls']:
                        resultado[x] = data_string['layers']['tls'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
