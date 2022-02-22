from django.urls import path

from applications.product.views import ProductListView

urlpatterns = [
    path('list/', ProductListView.as_view())
]
