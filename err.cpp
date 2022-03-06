In file included from /usr/include/c++/9/algorithm:62,
                 from /usr/include/c++/9/ext/slist:47,
                 from /usr/include/boost/algorithm/string/std/slist_traits.hpp:17,
                 from /usr/include/boost/algorithm/string/std_containers_traits.hpp:23,
                 from /usr/include/boost/algorithm/string.hpp:18,
                 from main.cpp:2:
/usr/include/c++/9/bits/stl_algo.h: In instantiation of ‘_OIter std::copy_if(_IIter, _IIter, _OIter, _Predicate) [with _IIter = std::__detail::_Node_iterator<std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >, false, true>; _OIter = std::__detail::_Node_iterator<std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >, false, true>; _Predicate = init_conn(pn::tcp::Connection)::<lambda(const auto:1&)>]’:
main.cpp:360:10:   required from here
/usr/include/c++/9/bits/stl_algo.h:751:16: error: use of deleted function ‘std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >& std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >::operator=(const std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >&)’
  751 |      *__result = *__first;
      |      ~~~~~~~~~~^~~~~~~~~~
In file included from /usr/include/c++/9/utility:70,
                 from /usr/include/c++/9/tuple:38,
                 from /usr/include/c++/9/functional:54,
                 from Polynet/polynet.hpp:26,
                 from main.cpp:1:
/usr/include/c++/9/bits/stl_pair.h:208:12: note: ‘std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >& std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >::operator=(const std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >&)’ is implicitly declared as deleted because ‘std::pair<const std::__cxx11::basic_string<char>, std::__cxx11::basic_string<char> >’ declares a move constructor or move assignment operator
  208 |     struct pair
      |            ^~~~
make: *** [Makefile:7: freedom] Error 1
