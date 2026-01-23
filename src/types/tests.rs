// Add tests for ReturnStack for VecStack
#[cfg(test)]
use crate::types::stack::ReturnStack;
use crate::types::stack::StaticStack;

macro_rules! underflow_test {
    ($n:ident, $stack_type:ty) => {
        #[test]
        fn $n() {
            let mut s = <$stack_type>::new(2).unwrap();
            assert_eq!(s.pop(), None);
            assert_eq!(s.depth(), 0);

            s.push(10);
            s.pop();
            assert_eq!(s.pop(), None);
        }
    };
}

macro_rules! return_stack_implementation {
    ($n:ident, $stack_type:ty) => {
        #[test]
        fn $n() {
            let mut s = <$stack_type>::new(3).unwrap();
            s.push(1);
            s.push(2);
            s.push(3);
            assert_eq!(s.depth(), 3);
            assert_eq!(s.max_depth(), 3);

            s.push(4);
            assert_eq!(s.depth(), 3);
            assert_eq!(s.pop(), Some(4));
            assert_eq!(s.pop(), Some(3));
            assert_eq!(s.pop(), Some(2));
            assert_eq!(s.pop(), None);
        }
    };
}

underflow_test!(static_stack_under, StaticStack<2>);
return_stack_implementation!(static_implementation, StaticStack<3>);

#[cfg(feature = "alloc")]
mod box_stack_test {
    use super::*;
    use crate::types::stack::BoxStack;

    return_stack_implementation!(boxstack_implementation, BoxStack);
    underflow_test!(boxstack_stack_under, BoxStack);
    #[test]
    fn test_box_return_stack() {
        let mut box_stack = BoxStack::new(3).unwrap();
        assert!(box_stack.pop().is_none(), "Expected box to be empty");
        box_stack.push(10);
        box_stack.push(555);
        box_stack.push(10000);

        assert_eq!(box_stack.pop(), Some(10000));
        assert_eq!(box_stack.pop(), Some(555));

        box_stack.push(35);
        assert_eq!(box_stack.pop(), Some(35));
        assert_eq!(box_stack.pop(), Some(10));
        assert_eq!(box_stack.pop(), None);
        assert_eq!(box_stack.pop(), None);
    }

    #[test]
    fn test_boxstack_zero_size() {
        let box_stack = BoxStack::new(0);
        assert!(box_stack.is_none());
    }
}

#[cfg(feature = "alloc")]
mod vec_stack_test {
    use super::*;
    use crate::types::stack::VecStack;

    #[test]
    fn test_aliases_vec_return_stack() {
        let mut vec_stack = VecStack::new(4).unwrap();
        vec_stack.push(5);
        vec_stack.push(10);
        vec_stack.push(15);

        assert_eq!(vec_stack.pop(), Some(15));
        assert_eq!(vec_stack.max_depth(), 4)
    }

    #[test]
    fn test_vec_push_overflow() {
        let mut vec_stack = VecStack::new(3).unwrap();
        vec_stack.push_back(5);
        vec_stack.push_back(10);
        vec_stack.push_back(15);
        vec_stack.push_front(0);

        assert_eq!(vec_stack.pop_back(), Some(10));
        assert_eq!(vec_stack.pop_front(), Some(0));
        assert_eq!(vec_stack.depth(), 1);
        assert_eq!(vec_stack.pop_back(), Some(5));
        assert_eq!(vec_stack.pop_back(), None);
    }

    #[test]
    fn test_vec_stack_reusability() {
        let mut vec_stack = VecStack::new(2).unwrap();
        vec_stack.push(1);
        vec_stack.push(2);
        vec_stack.pop();
        vec_stack.pop();
        vec_stack.push(3);
        assert_eq!(vec_stack.pop(), Some(3));
        assert_eq!(vec_stack.depth(), 0)
    }

    #[test]
    fn test_vec_zero_cap() {
        let mut vec_stack = VecStack::new(0).unwrap();
        vec_stack.push(1);
        assert_eq!(vec_stack.depth(), 0);
        assert_eq!(vec_stack.pop(), None);
    }
}

#[test]
fn none_return_static() {
    let s = StaticStack::<2>::new(3);
    assert!(s.is_none());
}
