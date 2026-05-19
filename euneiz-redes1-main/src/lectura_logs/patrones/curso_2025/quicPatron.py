from lectura_logs.PatronPadre import PatronPadre


class quicPatron(PatronPadre):
    '''
    Clase patrón del protocolo QUIC (Quick UDP Internet Connections).
    QUIC es el transporte subyacente de HTTP/3 y corre sobre UDP (normalmente puerto 443).
    Campos extraídos tanto de cabeceras largas (Initial/Handshake) como cortas (1-RTT).
    '''
    dict_values = [
        "layer_name",
        "version",           # quic.version         — versión QUIC (0x1=RFC9000, etc.)
        "header_form",       # quic.header_form      — 1=cabecera larga, 0=cabecera corta
        "long_packet_type",  # quic.long.packet_type — tipo en cabecera larga (0=Initial, 2=Handshake…)
        "packet_number",     # quic.packet_number    — número de paquete (decodificado)
        "packet_length",     # quic.packet_length    — longitud total del paquete QUIC
        "length",            # quic.length           — longitud de payload + número de paquete
        "dcid",              # quic.dcid             — Destination Connection ID
        "scid",              # quic.scid             — Source Connection ID
        "dcil",              # quic.dcil             — longitud del DCID
        "scil",              # quic.scil             — longitud del SCID
        "token_length",      # quic.token_length     — longitud del token (paquetes Initial)
        "spin_bit",          # quic.spin_bit         — bit de latencia (RFC 9000 §17.3.1)
        "key_phase",         # quic.key_phase        — fase de clave activa (cabecera corta)
        "frame_type",        # quic.frame_type       — tipo de frame dentro del paquete
        "connection_number", # quic.connection.number — ID de conexión en esta captura
    ]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'quic.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        if 'layers' in data_string:
            if 'quic' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['quic']:
                        resultado[x] = data_string['layers']['quic'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado
