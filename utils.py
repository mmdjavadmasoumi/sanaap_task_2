import redis
import random
from django.conf import settings


class RedisSingleton:
    _instance = None

    @staticmethod
    def get_instance():
        if RedisSingleton._instance is None:
            RedisSingleton._instance = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=int(settings.REDIS_PORT),
                db=int(settings.REDIS_DATABASE),
                decode_responses=True
            )
        return RedisSingleton._instance

redis_client = RedisSingleton.get_instance()


def generate_otp():
    return str(random.randint(100000, 999999))


def save_otp_to_redis(email, otp_code):
    redis_client.setex(f"otp:{email}", 600, otp_code)  # 10 minutes


def get_otp_from_redis(email):
    return redis_client.get(f"otp:{email}")


def delete_otp_from_redis(email):
    redis_client.delete(f"otp:{email}")
