
from lectura_logs.PatronPadre import PatronPadre


class httpPatron(PatronPadre):
    '''
    Clase patrón del protocolo HTTP (HyperText Transfer Protocol)
    '''
    dict_values = [
        "layer_name", "request_method", "request_uri", "request_version",
        "request_full_uri", "host", "user_agent", "accept",
        "content_type", "content_length", "response_code", "response_phrase", "server"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'http.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'http' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['http']:
                        resultado[x] = data_string['layers']['http'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
