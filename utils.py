# utils.py
import json

def load_attack_mapping(dataset='attack_dataset.json'):
    try:
        with open(dataset, 'r', encoding='utf-8') as f:
            data = json.load(f)

        id_to_technique = {}
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern' and 'external_references' in obj:
                for ref in obj['external_references']:
                    if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
                        ext_id = ref['external_id']
                        id_to_technique[ext_id] = {
                            'name': obj.get('name'),
                            'description': obj.get('description', ''),
                            'tactic': obj.get('kill_chain_phases', [{}])[0].get('phase_name', 'unknown'),
                            'url': ref.get('url', '')
                        }
        return id_to_technique

    except Exception as e:
        print(f"❌ Failed to load MITRE ATT&CK mapping: {e}")
        return {}
