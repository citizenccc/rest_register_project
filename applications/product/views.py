from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from applications.product.models import Product
from applications.product.serializers import ProductSerializer


class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated, ]