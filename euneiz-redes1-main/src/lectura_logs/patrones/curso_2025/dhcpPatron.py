from lectura_logs.PatronPadre import PatronPadre


class dhcpPatron(PatronPadre):
    '''
    Clase patrón del protocolo DHCP (Dynamic Host Configuration Protocol).
    Wireshark puede nombrar la capa 'dhcp' (v3+) o 'bootp' (versiones anteriores).
    '''
    dict_values = [
        "layer_name", "type", "hw_type", "hw_len", "hops", "id", "secs",
        "flags", "ip_client", "ip_your", "ip_server", "ip_relay",
        "hw_mac_addr", "option_dhcp", "option_hostname", "option_requested_ip_address"
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'dhcp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            # DHCP puede aparecer como 'dhcp' (Wireshark ≥3) o 'bootp' (versiones anteriores)
            layer_key = None
            if 'dhcp' in data_string['layers']:
                layer_key = 'dhcp'
            elif 'bootp' in data_string['layers']:
                layer_key = 'bootp'

            if layer_key:
                for x in resultado.keys():
                    if x in data_string['layers'][layer_key]:
                        resultado[x] = data_string['layers'][layer_key][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
