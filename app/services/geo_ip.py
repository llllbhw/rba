import geoip2.database
from flask import current_app  # 使用current_app替代直接导入app

def get_geo_location(ip_address):
    try:
        with geoip2.database.Reader(current_app.config['GEOIP_DATABASE_PATH']) as reader:
            response = reader.city(ip_address)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
    except Exception as e:
        current_app.logger.error(f"GeoIP lookup failed: {str(e)}")
        return None